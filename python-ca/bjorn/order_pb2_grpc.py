# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from . import order_pb2 as order__pb2


class CAStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.ValidateEAB = channel.unary_unary(
                '/cert_order.CA/ValidateEAB',
                request_serializer=order__pb2.ValidateEABRequest.SerializeToString,
                response_deserializer=order__pb2.ValidateEABResponse.FromString,
                )
        self.CreateOrder = channel.unary_unary(
                '/cert_order.CA/CreateOrder',
                request_serializer=order__pb2.CreateOrderRequest.SerializeToString,
                response_deserializer=order__pb2.OrderResponse.FromString,
                )
        self.GetOrder = channel.unary_unary(
                '/cert_order.CA/GetOrder',
                request_serializer=order__pb2.IDRequest.SerializeToString,
                response_deserializer=order__pb2.Order.FromString,
                )
        self.FinalizeOrder = channel.unary_unary(
                '/cert_order.CA/FinalizeOrder',
                request_serializer=order__pb2.FinalizeOrderRequest.SerializeToString,
                response_deserializer=order__pb2.OrderResponse.FromString,
                )
        self.GetAuthorization = channel.unary_unary(
                '/cert_order.CA/GetAuthorization',
                request_serializer=order__pb2.IDRequest.SerializeToString,
                response_deserializer=order__pb2.Authorization.FromString,
                )
        self.DeactivateAuthorization = channel.unary_unary(
                '/cert_order.CA/DeactivateAuthorization',
                request_serializer=order__pb2.IDRequest.SerializeToString,
                response_deserializer=order__pb2.AuthorizationResponse.FromString,
                )
        self.GetChallenge = channel.unary_unary(
                '/cert_order.CA/GetChallenge',
                request_serializer=order__pb2.ChallengeIDRequest.SerializeToString,
                response_deserializer=order__pb2.Challenge.FromString,
                )
        self.CompleteChallenge = channel.unary_unary(
                '/cert_order.CA/CompleteChallenge',
                request_serializer=order__pb2.CompleteChallengeRequest.SerializeToString,
                response_deserializer=order__pb2.ChallengeResponse.FromString,
                )
        self.GetCertificate = channel.unary_unary(
                '/cert_order.CA/GetCertificate',
                request_serializer=order__pb2.IDRequest.SerializeToString,
                response_deserializer=order__pb2.CertificateChainResponse.FromString,
                )
        self.RevokeCertificate = channel.unary_unary(
                '/cert_order.CA/RevokeCertificate',
                request_serializer=order__pb2.RevokeCertRequest.SerializeToString,
                response_deserializer=order__pb2.RevokeCertResponse.FromString,
                )


class CAServicer(object):
    """Missing associated documentation comment in .proto file."""

    def ValidateEAB(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def CreateOrder(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetOrder(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def FinalizeOrder(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetAuthorization(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeactivateAuthorization(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetChallenge(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def CompleteChallenge(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetCertificate(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def RevokeCertificate(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_CAServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'ValidateEAB': grpc.unary_unary_rpc_method_handler(
                    servicer.ValidateEAB,
                    request_deserializer=order__pb2.ValidateEABRequest.FromString,
                    response_serializer=order__pb2.ValidateEABResponse.SerializeToString,
            ),
            'CreateOrder': grpc.unary_unary_rpc_method_handler(
                    servicer.CreateOrder,
                    request_deserializer=order__pb2.CreateOrderRequest.FromString,
                    response_serializer=order__pb2.OrderResponse.SerializeToString,
            ),
            'GetOrder': grpc.unary_unary_rpc_method_handler(
                    servicer.GetOrder,
                    request_deserializer=order__pb2.IDRequest.FromString,
                    response_serializer=order__pb2.Order.SerializeToString,
            ),
            'FinalizeOrder': grpc.unary_unary_rpc_method_handler(
                    servicer.FinalizeOrder,
                    request_deserializer=order__pb2.FinalizeOrderRequest.FromString,
                    response_serializer=order__pb2.OrderResponse.SerializeToString,
            ),
            'GetAuthorization': grpc.unary_unary_rpc_method_handler(
                    servicer.GetAuthorization,
                    request_deserializer=order__pb2.IDRequest.FromString,
                    response_serializer=order__pb2.Authorization.SerializeToString,
            ),
            'DeactivateAuthorization': grpc.unary_unary_rpc_method_handler(
                    servicer.DeactivateAuthorization,
                    request_deserializer=order__pb2.IDRequest.FromString,
                    response_serializer=order__pb2.AuthorizationResponse.SerializeToString,
            ),
            'GetChallenge': grpc.unary_unary_rpc_method_handler(
                    servicer.GetChallenge,
                    request_deserializer=order__pb2.ChallengeIDRequest.FromString,
                    response_serializer=order__pb2.Challenge.SerializeToString,
            ),
            'CompleteChallenge': grpc.unary_unary_rpc_method_handler(
                    servicer.CompleteChallenge,
                    request_deserializer=order__pb2.CompleteChallengeRequest.FromString,
                    response_serializer=order__pb2.ChallengeResponse.SerializeToString,
            ),
            'GetCertificate': grpc.unary_unary_rpc_method_handler(
                    servicer.GetCertificate,
                    request_deserializer=order__pb2.IDRequest.FromString,
                    response_serializer=order__pb2.CertificateChainResponse.SerializeToString,
            ),
            'RevokeCertificate': grpc.unary_unary_rpc_method_handler(
                    servicer.RevokeCertificate,
                    request_deserializer=order__pb2.RevokeCertRequest.FromString,
                    response_serializer=order__pb2.RevokeCertResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'cert_order.CA', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class CA(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def ValidateEAB(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/ValidateEAB',
            order__pb2.ValidateEABRequest.SerializeToString,
            order__pb2.ValidateEABResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def CreateOrder(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/CreateOrder',
            order__pb2.CreateOrderRequest.SerializeToString,
            order__pb2.OrderResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetOrder(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/GetOrder',
            order__pb2.IDRequest.SerializeToString,
            order__pb2.Order.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def FinalizeOrder(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/FinalizeOrder',
            order__pb2.FinalizeOrderRequest.SerializeToString,
            order__pb2.OrderResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetAuthorization(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/GetAuthorization',
            order__pb2.IDRequest.SerializeToString,
            order__pb2.Authorization.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def DeactivateAuthorization(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/DeactivateAuthorization',
            order__pb2.IDRequest.SerializeToString,
            order__pb2.AuthorizationResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetChallenge(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/GetChallenge',
            order__pb2.ChallengeIDRequest.SerializeToString,
            order__pb2.Challenge.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def CompleteChallenge(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/CompleteChallenge',
            order__pb2.CompleteChallengeRequest.SerializeToString,
            order__pb2.ChallengeResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetCertificate(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/GetCertificate',
            order__pb2.IDRequest.SerializeToString,
            order__pb2.CertificateChainResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def RevokeCertificate(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.CA/RevokeCertificate',
            order__pb2.RevokeCertRequest.SerializeToString,
            order__pb2.RevokeCertResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)


class OCSPStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.CheckCert = channel.unary_unary(
                '/cert_order.OCSP/CheckCert',
                request_serializer=order__pb2.CheckCertRequest.SerializeToString,
                response_deserializer=order__pb2.CheckCertResponse.FromString,
                )


class OCSPServicer(object):
    """Missing associated documentation comment in .proto file."""

    def CheckCert(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_OCSPServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'CheckCert': grpc.unary_unary_rpc_method_handler(
                    servicer.CheckCert,
                    request_deserializer=order__pb2.CheckCertRequest.FromString,
                    response_serializer=order__pb2.CheckCertResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'cert_order.OCSP', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class OCSP(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def CheckCert(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.OCSP/CheckCert',
            order__pb2.CheckCertRequest.SerializeToString,
            order__pb2.CheckCertResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)


class ValidatorStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.ValidateHTTP01 = channel.unary_unary(
                '/cert_order.Validator/ValidateHTTP01',
                request_serializer=order__pb2.KeyValidationRequest.SerializeToString,
                response_deserializer=order__pb2.ValidationResult.FromString,
                )
        self.ValidateDNS01 = channel.unary_unary(
                '/cert_order.Validator/ValidateDNS01',
                request_serializer=order__pb2.KeyValidationRequest.SerializeToString,
                response_deserializer=order__pb2.ValidationResult.FromString,
                )
        self.ValidateTLSALPN01 = channel.unary_unary(
                '/cert_order.Validator/ValidateTLSALPN01',
                request_serializer=order__pb2.KeyValidationRequest.SerializeToString,
                response_deserializer=order__pb2.ValidationResult.FromString,
                )


class ValidatorServicer(object):
    """Missing associated documentation comment in .proto file."""

    def ValidateHTTP01(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ValidateDNS01(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ValidateTLSALPN01(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_ValidatorServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'ValidateHTTP01': grpc.unary_unary_rpc_method_handler(
                    servicer.ValidateHTTP01,
                    request_deserializer=order__pb2.KeyValidationRequest.FromString,
                    response_serializer=order__pb2.ValidationResult.SerializeToString,
            ),
            'ValidateDNS01': grpc.unary_unary_rpc_method_handler(
                    servicer.ValidateDNS01,
                    request_deserializer=order__pb2.KeyValidationRequest.FromString,
                    response_serializer=order__pb2.ValidationResult.SerializeToString,
            ),
            'ValidateTLSALPN01': grpc.unary_unary_rpc_method_handler(
                    servicer.ValidateTLSALPN01,
                    request_deserializer=order__pb2.KeyValidationRequest.FromString,
                    response_serializer=order__pb2.ValidationResult.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'cert_order.Validator', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class Validator(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def ValidateHTTP01(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.Validator/ValidateHTTP01',
            order__pb2.KeyValidationRequest.SerializeToString,
            order__pb2.ValidationResult.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def ValidateDNS01(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.Validator/ValidateDNS01',
            order__pb2.KeyValidationRequest.SerializeToString,
            order__pb2.ValidationResult.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def ValidateTLSALPN01(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/cert_order.Validator/ValidateTLSALPN01',
            order__pb2.KeyValidationRequest.SerializeToString,
            order__pb2.ValidationResult.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
