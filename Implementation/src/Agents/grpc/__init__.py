"""
gRPC tier-agent scaffold.

Status: proto + server/client skeleton only. To adopt for real:
  1. `pip install grpcio grpcio-tools`
  2. Generate stubs: `python -m grpc_tools.protoc -I . --python_out=. --grpc_python_out=. tier_agent.proto`
  3. Fill TierAgentServicer.Process with the actual Tier1/2/3 dispatch.
  4. Replace RemoteAgentClient HTTP calls with GrpcTierClient.

Why bother: the current HTTP path has 2s connect + 15s read timeouts that
serialise every tier handoff. gRPC streams + HTTP/2 multiplexing bring that
close to zero overhead and support backpressure.
"""
