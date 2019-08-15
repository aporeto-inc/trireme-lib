package common

// Values for hook methods
const (
	MetadataHookPolicy      = "metadata:policy"
	MetadataHookHealth      = "metadata:health"
	MetadataHookCertificate = "metadata:certificate"
	MetadataHookKey         = "metadata:key"
	MetadataHookToken       = "metadata:token"
	AWSHookInfo             = "aws:info"
	AWSHookRole             = "aws:role"
)

// AWSRole reserved prefix
const (
	AWSRoleARNPrefix = "@awsrole=arn:aws:iam::"

	AWSRolePrefix = "@awsrole="
)
