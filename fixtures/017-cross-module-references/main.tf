module "data" {
  source = "./modules/data"
  name   = "acme-claims-111122223333"
}

module "iam" {
  source     = "./modules/iam"
  bucket_arn = module.data.bucket_arn
}

module "web" {
  source           = "./modules/web"
  instance_profile = module.iam.instance_profile_name
}
