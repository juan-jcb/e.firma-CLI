'''
Modulo dedicado para modificaciones del código de otras librerías de python para tropicalizarlos a las
necesidades de éste programa xD.
'''

'''Monkey patching para leer certificados x509 del SAT con los campos x500UniqueIdentifier= mal codificados.
Cambio de: 'x509.OctetBitString' a: 'x509.DirectoryString'''
from asn1crypto import x509
x509.NameTypeAndValue._oid_specs['unique_identifier'] = x509.DirectoryString

'''Monkey patching sobre el método: "pyhanko.sign.timestamps.aiohttp_client.AIOHttpTimeStamper.async_request_tsa_response()"
Para ser más permisivo con las respuestas de la TSA en el header HTTP 'Content-Type' (application/xxxx)'''
import aiohttp
from asn1crypto import tsp
from pyhanko.sign.timestamps import TimestampRequestError

async def permisive_async_request_tsa_response(
    self, req: tsp.TimeStampReq
) -> tsp.TimeStampResp:
    session = await self.get_session()

    cl_timeout = aiohttp.ClientTimeout(total=self.timeout)
    headers = await self.async_request_headers()
    try:
        async with session.post(
            url=self.url,
            headers=headers,
            data=req.dump(),
            auth=self.auth,
            raise_for_status=True,
            timeout=cl_timeout,
        ) as response:
            response_data = await response.read()
            ct = response.headers.get('Content-Type')

            # "timestamp-response" NO es lo estándar según RFC 3161, pero se modifica tal que así para ser
            # permisivos con la TSA. timestamp-reply ES la respuesta oficial.
            if (ct == 'application/timestamp-reply') or (ct == 'application/timestamp-response'):
                pass
            else:
                msg = (
                    f'Bad content type. Expected '
                    f'application/timestamp-reply or application/timestamp-response,but got {ct}.'
                )
                raise aiohttp.ContentTypeError(
                    response.request_info,
                    response.history,
                    message=msg,
                    headers=response.headers,
                )

    except aiohttp.ClientError as e:
        raise TimestampRequestError(
            "Error while contacting timestamp service",
        ) from e
    return tsp.TimeStampResp.load(response_data)

from pyhanko.sign.timestamps import aiohttp_client
aiohttp_client.AIOHttpTimeStamper.async_request_tsa_response = permisive_async_request_tsa_response
