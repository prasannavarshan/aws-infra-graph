"""Tests for CloudFormation PhysicalResourceId to ARN mapping."""

from src.collector.cloudformation_arn import physical_id_to_arn

ACCOUNT = "123456789012"
REGION = "us-east-1"


class TestArnMapping:
    """Tests for known resource type mappings."""

    def test_ec2_instance(self):
        arn = physical_id_to_arn(
            "AWS::EC2::Instance", "i-0abc123", REGION, ACCOUNT,
        )
        assert arn == (
            f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0abc123"
        )

    def test_lambda_function(self):
        arn = physical_id_to_arn(
            "AWS::Lambda::Function", "my-func", REGION, ACCOUNT,
        )
        assert arn == (
            f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:my-func"
        )

    def test_s3_bucket(self):
        arn = physical_id_to_arn(
            "AWS::S3::Bucket", "my-bucket", REGION, ACCOUNT,
        )
        assert arn == "arn:aws:s3:::my-bucket"

    def test_sqs_queue_url(self):
        url = (
            "https://sqs.us-east-1.amazonaws.com"
            "/123456789012/my-queue"
        )
        arn = physical_id_to_arn(
            "AWS::SQS::Queue", url, REGION, ACCOUNT,
        )
        assert arn == (
            f"arn:aws:sqs:{REGION}:{ACCOUNT}:my-queue"
        )

    def test_security_group(self):
        arn = physical_id_to_arn(
            "AWS::EC2::SecurityGroup", "sg-abc123",
            REGION, ACCOUNT,
        )
        assert arn == (
            f"arn:aws:ec2:{REGION}:{ACCOUNT}"
            f":security-group/sg-abc123"
        )

    def test_iam_role(self):
        arn = physical_id_to_arn(
            "AWS::IAM::Role", "MyRole", REGION, ACCOUNT,
        )
        assert arn == f"arn:aws:iam::{ACCOUNT}:role/MyRole"

    def test_rds_instance(self):
        arn = physical_id_to_arn(
            "AWS::RDS::DBInstance", "mydb", REGION, ACCOUNT,
        )
        assert arn == (
            f"arn:aws:rds:{REGION}:{ACCOUNT}:db:mydb"
        )


class TestPassthrough:
    """Tests for ARN passthrough and edge cases."""

    def test_arn_passthrough(self):
        """PhysicalResourceId that is already an ARN returns as-is."""
        existing_arn = (
            f"arn:aws:sns:{REGION}:{ACCOUNT}:my-topic"
        )
        result = physical_id_to_arn(
            "AWS::SNS::Topic", existing_arn, REGION, ACCOUNT,
        )
        assert result == existing_arn

    def test_unknown_type_returns_none(self):
        result = physical_id_to_arn(
            "AWS::CloudWatch::Alarm", "my-alarm",
            REGION, ACCOUNT,
        )
        assert result is None

    def test_empty_physical_id_returns_none(self):
        result = physical_id_to_arn(
            "AWS::EC2::Instance", "", REGION, ACCOUNT,
        )
        assert result is None

    def test_nested_stack_passthrough(self):
        """Nested stack PhysicalResourceId IS the child stack ARN."""
        child_arn = (
            f"arn:aws:cloudformation:{REGION}:{ACCOUNT}"
            f":stack/child-stack/guid-123"
        )
        result = physical_id_to_arn(
            "AWS::CloudFormation::Stack", child_arn,
            REGION, ACCOUNT,
        )
        assert result == child_arn
