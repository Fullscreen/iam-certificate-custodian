#!/usr/bin/env python
import os, sys
from datetime import datetime

sys.path.insert(0, './lib')
import boto3,  pytz

aws_region = os.environ.get('AWS_REGION', 'us-east-1')
iam = boto3.client('iam', region_name=aws_region)

def is_expired(cert):
  return cert['Expiration'] < datetime.now(pytz.utc)

def delete_certificate(cert):
  iam.delete_server_certificate

def get_certififcates_from_listeners(listeners):
  certificates = []
  for listener in listeners:
    if 'Listener' in listener:
      listener = listener['Listener']
    if 'SSLCertificateId' in listener:
      certificates.append(listener['SSLCertificateId'])
    if 'Certificates' in listener:
      for cert in listener['Certificates']:
        certificates.append(cert['CertificateArn'])
  return certificates

def get_cloudfront_certificates(iam_certificate_id_map):
  certificates = set()
  cf = boto3.client('cloudfront', region_name=aws_region)
  resp = cf.list_distributions()
  dists = resp['DistributionList']['Items']
  for dist in dists:
    cert = dist.get('ViewerCertificate', {})
    cert_id = cert.get('IAMCertificateId', None)
    if cert_id and cert_id in iam_certificate_id_map:
      certificates.add(iam_certificate_id_map[cert_id])
    if 'ACMCertificateArn' in cert:
      certificates.add(cert['ACMCertificateArn'])
  return certificates

def cleanup(event, context):
  active_certificates = set()
  elb = boto3.client('elb', region_name=aws_region)
  alb = boto3.client('elbv2', region_name=aws_region)

  # fetch certificates
  resp = iam.list_server_certificates()
  iam_certificates = resp['ServerCertificateMetadataList']

  # compile a map of IAM certificate ID's
  certificate_ids = {}
  for cert in iam_certificates:
    certificate_ids[cert['ServerCertificateId']] = cert['Arn']

  # get cloudfront certificates
  cloudfront_certs = get_cloudfront_certificates(certificate_ids)
  active_certificates.update(cloudfront_certs)

  # get elb (classic) certificates
  resp = elb.describe_load_balancers()
  elbs = resp['LoadBalancerDescriptions']

  for lb in elbs:
    descriptions = lb.get('ListenerDescriptions', [])
    certificates = get_certififcates_from_listeners(descriptions)
    active_certificates.update(certificates)

  # get elbv2 certificates
  resp = alb.describe_load_balancers()
  albs = resp['LoadBalancers']

  for lb in albs:
    resp = alb.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
    certificates = get_certififcates_from_listeners(resp['Listeners'])
    active_certificates.update(certificates)

  print('Detected certificates in use: {}'.format(', '.join(active_certificates)))

  for cert in iam_certificates:
    cert_arn = cert['Arn']
    cert_name = cert['ServerCertificateName']

    if cert_name.startswith(os.environ.get('CERTIFICATE_PREFIX', '')):
      if cert_arn not in active_certificates:
        if os.environ.get('DELETE_UNUSED_CERTIFICATES', 'false') == 'true':
          print("DELETE", cert_arn)
        elif is_expired(cert):
          print("DELETE", cert_arn)
