package events

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

// loadAWSConfig arma la configuración del SDK con la cadena estándar:
// variables de entorno (AWS_REGION, AWS_ACCESS_KEY_ID, AWS_ENDPOINT_URL...),
// archivos ~/.aws, y el rol de la tarea de ECS en producción.
// Nada de endpoints ni llaves en el YAML ni en el código.
func loadAWSConfig(ctx context.Context) (aws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Config{}, fmt.Errorf("cargando la configuración de AWS: %w", err)
	}
	if cfg.Region == "" {
		return aws.Config{}, errors.New("falta la región de AWS: define AWS_REGION (ej. us-east-1)")
	}
	// Falla rápido si no hay credenciales, en vez de descubrirlo en el primer batch.
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := cfg.Credentials.Retrieve(cctx); err != nil {
		return aws.Config{}, fmt.Errorf("sin credenciales de AWS (AWS_ACCESS_KEY_ID y AWS_SECRET_ACCESS_KEY, o un rol): %w", err)
	}
	return cfg, nil
}

func newSQSClient(ctx context.Context) (*sqs.Client, error) {
	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return nil, err
	}
	return sqs.NewFromConfig(cfg), nil
}

func newKinesisClient(ctx context.Context) (*kinesis.Client, error) {
	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return nil, err
	}
	return kinesis.NewFromConfig(cfg), nil
}

func NewSQSClient(ctx context.Context) (*sqs.Client, error) {
	return newSQSClient(ctx)
}
