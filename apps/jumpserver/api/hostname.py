from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny


## 此 api 返回 /etc/hostname 的值， 可以匿名访问
class HostnameView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        try:
            with open('/etc/hostname', 'r') as f:
                hostname = f.read().strip() or "Unknown"
            return Response({"hostname": hostname})
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
