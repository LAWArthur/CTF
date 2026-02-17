from ds_store import DSStore

# 打开 .DS_Store 文件
with DSStore.open(r"C:\Users\jinca\Downloads\DS_Store", 'r+') as ds:
    for entry in ds:
        print(f"文件名: {entry.filename}")
        print(f"类型: {entry.type}")
        print(f"代码: {entry.code}")
        print(f"值: {entry.value}")
        print("-" * 50)