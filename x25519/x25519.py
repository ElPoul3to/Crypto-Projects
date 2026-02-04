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

# --- Test Functions --- # (Generated with LLM)
def test_curve_operations():
    """
    Test xDBL, xADD, and ladder functions using the given test vectors.
    Base point P = (9:*:1)
    """
    print("=== Testing Curve25519 Operations ===\n")
    
    # Test vectors
    base_x = 9
    base_z = 1
    
    test_vectors = {
        2: 14847277145635483483963372537557091634710985132825781088887140890597596352251,
        3: 12697861248284385512127539163427099897745340918349830473877503196793995869202,
        4: 55094879196667521951171181671895976763495004283458921215716618814842818532335,
        5: 29723531761959712214579609737676588517305008794118309711793522224007834336391,
        7: 6189616607995615193367150877376005513902989163470402290395604116858034460712
    }
    
    all_passed = True
    
    # Test [2]P using xDBL
    print("Testing [2]P with xDBL:")
    x_2, z_2 = xDBL(base_x, base_z)
    x_2_affine = (x_2 * pow(z_2, P - 2, P)) % P
    expected_2 = test_vectors[2]
    if x_2_affine == expected_2:
        print(f"  ✓ [2]P = {x_2_affine}")
        print(f"  Expected: {expected_2}")
        print(f"  PASS\n")
    else:
        print(f"  ✗ [2]P = {x_2_affine}")
        print(f"  Expected: {expected_2}")
        print(f"  FAIL\n")
        all_passed = False
    
    # Test [3]P using xADD ([2]P + P, difference = P)
    print("Testing [3]P with xADD ([2]P + P):")
    x_3, z_3 = xADD(x_2, z_2, base_x, base_z, base_x)
    x_3_affine = (x_3 * pow(z_3, P - 2, P)) % P
    expected_3 = test_vectors[3]
    if x_3_affine == expected_3:
        print(f"  ✓ [3]P = {x_3_affine}")
        print(f"  Expected: {expected_3}")
        print(f"  PASS\n")
    else:
        print(f"  ✗ [3]P = {x_3_affine}")
        print(f"  Expected: {expected_3}")
        print(f"  FAIL\n")
        all_passed = False
    
    # Test [4]P using xDBL ([2][2]P)
    print("Testing [4]P with xDBL ([2][2]P):")
    x_4, z_4 = xDBL(x_2, z_2)
    x_4_affine = (x_4 * pow(z_4, P - 2, P)) % P
    expected_4 = test_vectors[4]
    if x_4_affine == expected_4:
        print(f"  ✓ [4]P = {x_4_affine}")
        print(f"  Expected: {expected_4}")
        print(f"  PASS\n")
    else:
        print(f"  ✗ [4]P = {x_4_affine}")
        print(f"  Expected: {expected_4}")
        print(f"  FAIL\n")
        all_passed = False
    
    # Test ladder for all multiples
    print("Testing ladder for multiples [2]P through [7]P:")
    for k in [2, 3, 4, 5, 7]:
        x_k, z_k = ladder(k, (base_x, base_z))
        x_k_affine = (x_k * pow(z_k, P - 2, P)) % P
        expected_k = test_vectors[k]
        
        if x_k_affine == expected_k:
            print(f"  ✓ [{k}]P = {x_k_affine}")
            print(f"    Expected: {expected_k}")
            print(f"    PASS")
        else:
            print(f"  ✗ [{k}]P = {x_k_affine}")
            print(f"    Expected: {expected_k}")
            print(f"    FAIL")
            all_passed = False
    
    print("\n" + "="*50)
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print("="*50)
    
    return all_passed


def test_iterative_vectors():
    """
    Test X25519 using iterative test vectors.
    Initially, set k and u to: 0900000000000000000000000000000000000000000000000000000000000000
    For each iteration:
      - Call X25519(k, u)
      - Set k to the result
      - Set u to the old value of k
    """
    print("=== Testing X25519 Iterative Vectors ===\n")
    
    initial_hex = "0900000000000000000000000000000000000000000000000000000000000000"
    k_bytes = bytes.fromhex(initial_hex)
    u_bytes = bytes.fromhex(initial_hex)
    
    test_vectors = {
        1: "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
        1000000: "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
    }
    
    all_passed = True
    max_iterations = 1000000
    
    print(f"Running {max_iterations:,} iterations...")
    print(f"Initial k and u: {initial_hex}\n")
    
    for i in range(1, max_iterations + 1):
        k = decodeScalar25519(k_bytes)
        u = decodeUCoordinate(u_bytes)
        
        x_res, z_res = ladder(k, (u, 1))
        result_x = (x_res * pow(z_res, P - 2, P)) % P
        result_bytes = encodeUCoordinate(result_x)
        
        u_bytes = k_bytes
        k_bytes = result_bytes
        
        if i in test_vectors:
            result_hex = result_bytes.hex()
            expected_hex = test_vectors[i]
            
            if result_hex == expected_hex:
                print(f"✓ After {i:,} iteration(s):")
                print(f"  Result:   {result_hex}")
                print(f"  Expected: {expected_hex}")
                print(f"  PASS\n")
            else:
                print(f"✗ After {i:,} iteration(s):")
                print(f"  Result:   {result_hex}")
                print(f"  Expected: {expected_hex}")
                print(f"  FAIL\n")
                all_passed = False
        
        if i % 100000 == 0:
            print(f"  ... {i:,} iterations completed")
    
    print("="*50)
    if all_passed:
        print("✓ ALL ITERATIVE TESTS PASSED")
    else:
        print("✗ SOME ITERATIVE TESTS FAILED")
    print("="*50)
    
    return all_passed


# --- Programme Principal X25519 --- #
def main():
    if len(sys.argv) not in [2, 3]:
        print("Usage: ./x25519.py <scalar_hex> [u_coord_hex]")
        print("       ./x25519.py --test  (to run curve operations test vectors)")
        print("       ./x25519.py --test-iter  (to run iterative test vectors)")
        sys.exit(1)

    if sys.argv[1] == "--test":
        test_curve_operations()
        sys.exit(0)
        
    if sys.argv[1] == "--test-iter":
        test_iterative_vectors()
        sys.exit(0)

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