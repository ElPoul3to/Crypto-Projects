#!/usr/bin/env python3
import sys

# --- Constantes Globales --- #
P = 2**255 - 19
A24 = 121665

# --- Fonctions Utilitaires --- #
def mask(swap):
    # Retourne -1 (tous les bits à 1) si swap=1, sinon 0
    return -swap

def cswap(swap, x_2, x_3):
    dummy = mask(swap) & (x_2 ^ x_3)
    x_2 = x_2 ^ dummy
    x_3 = x_3 ^ dummy
    return x_2, x_3

# --- Arithmétique de Courbe (Montgomery) --- #
def xDBL(x_P, z_P):
    A = (x_P + z_P) % P
    AA = pow(A, 2, P)
    B = (x_P - z_P) % P
    BB = pow(B, 2, P)
    E = (AA - BB) % P
    x_2P = (AA * BB) % P
    z_2P = (E * (AA + A24 * E)) % P
    return x_2P, z_2P

def xADD(x_P, z_P, x_Q, z_Q, x_diff):
    A = (x_P + z_P) % P
    B = (x_P - z_P) % P
    C = (x_Q + z_Q) % P
    D = (x_Q - z_Q) % P
    DA = (D * A) % P
    CB = (C * B) % P
    x_P_plus_Q = pow(DA + CB, 2, P)
    z_P_plus_Q = (x_diff * pow(DA - CB, 2, P)) % P
    return x_P_plus_Q, z_P_plus_Q

def ladder(m, point_coords):
    """
    Échelle de Montgomery (RFC 7748)
    m : le scalaire (entier)
    point_coords : tuple (X, Z) du point sur la courbe
    """
    x_1, z_1 = point_coords
    
    x_2, z_2 = 1, 0
    x_3, z_3 = x_1, z_1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (m >> t) & 1
        swap ^= k_t
        
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t
        
        # Store original values before modification
        x_2_orig, z_2_orig = x_2, z_2
        
        x_2, z_2 = xDBL(x_2, z_2)
        x_3, z_3 = xADD(x_2_orig, z_2_orig, x_3, z_3, x_1)

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    
    return x_2, z_2

# --- Encodage / Décodage (RFC 7748) --- #
def decodeScalar25519(k_bytes):
    k_list = bytearray(k_bytes)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return int.from_bytes(k_list, 'little')

def decodeUCoordinate(u_bytes):
    u_list = bytearray(u_bytes)
    u_list[31] &= 127
    return int.from_bytes(u_list, 'little')

def encodeUCoordinate(u):
    u = u % P
    return u.to_bytes(32, 'little')

# --- Programme Principal X25519 --- #
def main():
    if len(sys.argv) not in [2, 3]:
        print("Usage: ./x25519.py <scalar_hex> [u_coord_hex]")
        sys.exit(1)

    m_hex = sys.argv[1]
    try:
        m_bytes = bytes.fromhex(m_hex)
        if len(m_bytes) != 32:
            raise ValueError("La longueur doit être de 32 octets")
    except ValueError:
        print("Erreur: Le scalaire doit être une chaîne hexadécimale de 32 octets.")
        sys.exit(1)
        
    m = decodeScalar25519(m_bytes)

    if len(sys.argv) == 3:
        u_hex = sys.argv[2]
        try:
            u_bytes = bytes.fromhex(u_hex)
            if len(u_bytes) != 32:
                 raise ValueError("La longueur doit être de 32 octets")
        except ValueError:
            print("Erreur: La coordonnée u doit être une chaîne hexadécimale de 32 octets.")
            sys.exit(1)
        u = decodeUCoordinate(u_bytes)
    else:
        u = 9

    x_res, z_res = ladder(m, (u, 1))

    result_x = (x_res * pow(z_res, P - 2, P)) % P

    output_hex = encodeUCoordinate(result_x).hex()
    print(output_hex)

if __name__ == "__main__":
    main()