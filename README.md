# irene
AWS Permission Management System


# description
ACL of the S3 buckets or the folders in the bucket can be managed with this system ( irene ).
The subject of ACL is IAMUser or IAMRole.
The permission of ACL is some s3:actions that are defined on the document of AWS S3 policy.
Irene provide the function to make the abstract permission like 'READ' or 'WRITE' such as them of the linux or hdfs by merging some of the s3:actions.

# usage
API or UI

# installation
terraform scripts

# architecture
backend : rest API ( apigw + lambda )
frontend : vue on ec2


