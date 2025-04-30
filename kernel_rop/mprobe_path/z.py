fn = "go"

with open(fn, "rb") as f:
    data = f.read()

print("'{}'".format(",".join("0x{:02x}".format(c) for c in data)))