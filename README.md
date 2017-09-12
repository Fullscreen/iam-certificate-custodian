iam-certificate-custodian
=========================

Deploy
======
This is a serverless application. You can deploy it to your AWS account with
following:

```shell
make && serverless deploy
```

Configure
=========

#### Deleting unused certificates
Use the `DELETE_UNUSED_CERTIFICATES` environment variable in the serverless.yml
file to control deletion of unexpired certificates that are not associated with
a cloudfront distribution or elastic load balancer. The default is to leave these
certificates in place unless they are expired.

#### Limiting deletions by prefix
Use the `CERTIFICATE_PREFIX` environment variable in the serverless.yml file
to control which certificates are eligible for deletion. The default prefix
for certificate names is `letsencrypt`.
