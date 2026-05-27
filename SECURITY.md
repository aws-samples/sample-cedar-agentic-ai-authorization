# Security

## Reporting a Vulnerability

If you discover a potential security issue in this project, we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).

Please do **not** create a public GitHub issue for security vulnerabilities.

## Security Best Practices

When deploying this solution:

- Rotate the HMAC signing key in AWS Secrets Manager regularly
- Monitor the Amazon CloudWatch alarms configured by the MonitoringStack
- Review Cedar policies periodically to ensure least-privilege alignment
- Enable AWS CloudTrail for API-level audit logging
- Restrict access to the AWS KMS customer-managed key via key policy
- Use the Amazon Cognito TOTP MFA enforcement for all human operators
