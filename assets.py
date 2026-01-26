from pathlib import Path
import base64

ACCESS_LOG_FORMAT = (
    '{"requestId":"$context.requestId",'
    '"ip":"$context.identity.sourceIp",'
    '"requestTime":"$context.requestTime",'
    '"httpMethod":"$context.httpMethod",'
    '"path":"$context.path",'
    '"status":"$context.status",'
    '"protocol":"$context.protocol",'
    '"responseLength":"$context.responseLength",'
    '"errorMessage":"$context.error.message"}'
)

bg_svg_path = Path(__file__).parent / "cognito-branding" / "bg.svg"
bg_svg_b64 = base64.b64encode(bg_svg_path.read_bytes()).decode("utf-8")