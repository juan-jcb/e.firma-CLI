# 'monkey patching' para leer certificados x509 del SAT con los campos x500UniqueIdentifier=
# mal codificados. Cambio de: 'asn1_x509.OctetBitString' a: 'asn1_x509.DirectoryString
from asn1crypto import x509 as asn1_x509
asn1_x509.NameTypeAndValue._oid_specs['unique_identifier'] = asn1_x509.DirectoryString

import sys
from efcli import conmutador

def main():
    conmutador.entrada(sys.argv)

if __name__ == "__main__":
    main()
