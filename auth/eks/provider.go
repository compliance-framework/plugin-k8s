package eks

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/compliance-framework/plugin-k8s/auth"
	"k8s.io/client-go/rest"
)

const (
	StsTokenPrefix  = "k8s-aws-v1."
	clusterIDHeader = "x-k8s-aws-id"
)

// TokenGenerator produces a bearer token for Kubernetes API authentication.
type TokenGenerator interface {
	GetToken(ctx context.Context, clusterName string) (string, error)
}

// EKSDescriber fetches EKS cluster details (endpoint + CA).
type EKSDescriber interface {
	DescribeCluster(ctx context.Context, clusterName string) (endpoint string, caData []byte, err error)
}

// STSTokenGenerator generates bearer tokens via STS presigned GetCallerIdentity.
type STSTokenGenerator struct {
	Client *sts.PresignClient
}

// GetToken creates a presigned STS URL and encodes it as a K8s bearer token.
func (g *STSTokenGenerator) GetToken(ctx context.Context, clusterName string) (string, error) {
	presigned, err := g.Client.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(opts *sts.PresignOptions) {
		opts.ClientOptions = append(opts.ClientOptions, func(o *sts.Options) {
			o.APIOptions = append(o.APIOptions, smithyhttp.AddHeaderValue(clusterIDHeader, clusterName))
		})
	})
	if err != nil {
		return "", fmt.Errorf("failed to presign GetCallerIdentity: %w", err)
	}
	token := StsTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(presigned.URL))
	return token, nil
}

// DefaultEKSDescriber describes an EKS cluster via the AWS SDK.
type DefaultEKSDescriber struct {
	Client *awseks.Client
}

// DescribeCluster returns endpoint and CA data for a given cluster.
func (d *DefaultEKSDescriber) DescribeCluster(ctx context.Context, clusterName string) (string, []byte, error) {
	output, err := d.Client.DescribeCluster(ctx, &awseks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to describe cluster %q: %w", clusterName, err)
	}
	cluster := output.Cluster
	if cluster == nil || cluster.Endpoint == nil || cluster.CertificateAuthority == nil || cluster.CertificateAuthority.Data == nil {
		return "", nil, fmt.Errorf("cluster %q returned incomplete data", clusterName)
	}
	caBytes, err := base64.StdEncoding.DecodeString(*cluster.CertificateAuthority.Data)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode CA for cluster %q: %w", clusterName, err)
	}
	return *cluster.Endpoint, caBytes, nil
}

// Provider implements auth.AuthProvider using aws-sdk-go-v2.
type Provider struct{}

// BuildRESTConfig authenticates to an EKS cluster and returns a rest.Config.
func (p *Provider) BuildRESTConfig(ctx context.Context, cluster auth.ClusterConfig) (*rest.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cluster.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for cluster %q: %w", cluster.Name, err)
	}

	if cluster.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, cluster.RoleARN)
	}

	eksClient := awseks.NewFromConfig(cfg)
	describer := &DefaultEKSDescriber{Client: eksClient}
	endpoint, caData, err := describer.DescribeCluster(ctx, cluster.ClusterName)
	if err != nil {
		return nil, err
	}

	stsClient := sts.NewFromConfig(cfg)
	presignClient := sts.NewPresignClient(stsClient)
	tokenGen := &STSTokenGenerator{Client: presignClient}
	token, err := tokenGen.GetToken(ctx, cluster.ClusterName)
	if err != nil {
		return nil, err
	}

	return &rest.Config{
		Host:        endpoint,
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caData,
		},
	}, nil
}
