from key_management import generate_ecc_keypair

def main():
    print("=== Key Generation ===")
    
    entity_id = input("Enter ID for key generation (e.g., 'Rahul', 'Ravi'): ").strip()
        
    if not entity_id:
        print("ID cannot be empty. Try again.")
        
    generate_ecc_keypair(entity_id)
    print(f"Keys generated successfully for {entity_id}.\n")


if __name__ == "__main__":
    main()
