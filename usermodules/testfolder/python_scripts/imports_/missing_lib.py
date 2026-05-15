from faker import Faker

fake = Faker()

print(f"Name: {fake.name()}")
print(f"Address: {fake.address()}")
print(f"Email: {fake.email()}")