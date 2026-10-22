terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    # finding #19: generates the control-plane's own WARREN_SECRET_KEY (see
    # random_password.warren_secret_key in main.tf) instead of deferring it to a
    # runbook that needs a plaintext env override on a one-off run-task call. R20
    # investigated replacing this with a Secrets Manager generate_secret_string
    # equivalent (as CDK already does) but found no such argument on this provider's
    # resources — see the comment above random_password.warren_secret_key in main.tf.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
