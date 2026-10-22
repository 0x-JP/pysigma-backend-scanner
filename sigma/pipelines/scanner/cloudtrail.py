from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation


def scanner_cloudtrail_pipeline():
    return ProcessingPipeline(
        name="Scanner CloudTrail (ECS normalization)",
        priority=20,
        allowed_backends=frozenset({"scanner"}),
        items=[ProcessingItem(
            identifier="scanner_cloudtrail_fields",
            rule_conditions=[LogsourceCondition(product="aws", service="cloudtrail")],
            transformation=FieldMappingTransformation({
                "eventName": "@ecs.event.action",
                "eventSource": "@ecs.cloud.service.name",
                "awsRegion": "@ecs.cloud.region",
                "recipientAccountId": "@ecs.cloud.account.id",
                "requestID": "@ecs.http.request_id",
                "userAgent": "@ecs.user_agent",
                "userIdentity.arn": "@ecs.user.id",
                "userIdentity.userName": "@ecs.user.name",
            }),
        )],
    )
