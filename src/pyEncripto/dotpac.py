"""
.pac structure:
[ MAGIC     ] 9 bytes
[ VERSION   ] 4 bytes
[ COUNT     ] 4 bytes
[ INDEX     ] 48 bytes * count
[ DATA      ]
...
[ DATA      ]

"""
import hashlib
import struct
import mmap
import io
from pathlib import Path


MAGIC = b'PYENCRIPTO'  # для проверки что формат наш
VERSION = 1  # версия энкриптора


def hash_name(name: str, key:bytes) -> bytes:
    """
    Хеширует путь к файлу (относительно корня ассетов) с помощью SHA-256.
	Используется вместо хранения оригинального имени в индексе — это:
	•	Защищает от анализа содержимого
	•	Позволяет делать поиск по хешу
    """
    
    return hashlib.sha256(key + name.encode()).digest()


# ====== Build .pac file ======
def build_pak(encriptor, key:bytes, asset_dir, out_file):
    """
    •	asset_dir: путь к папке с ассетами (например, assets/)
	•	out_file: путь к выходному .pak
	•	key: ключ шифрования
	•	encrypt_fn: функция encrypt(data: bytes, key: bytes) -> bytes
    """
    asset_dir = Path(asset_dir)
    files = list(asset_dir.rglob("*.*"))

    index = []  # список метаданных — (хеш, смещение, длина)
    data_chunks = []  # зашифрованные байты файлов
    offset = 0


    """
    •	Получаем относительный путь rel
	•	Читаем байты файла → шифруем → сохраняем длину и смещение
	•	Добавляем зашифрованный блок в список
    """
    for f in files:
        rel = str(f.relative_to(asset_dir)).replace("\\", "/")
        raw = f.read_bytes()
        enc = encriptor(raw, key)

        hname = hash_name(rel, key)
        index.append((hname, offset, len(enc)))
        data_chunks.append(enc)
        offset += len(enc)


    # Write .pak file
    with open(out_file, "wb") as out:
        out.write(MAGIC)                          # 9 байт сигнатуры
        out.write(struct.pack("<I", VERSION))     # 4 байта версия
        out.write(struct.pack("<I", len(index)))  # 4 байта число файлов

        for hname, offset, length in index:
            out.write(hname)  # 32 bytes хеш имя
            out.write(struct.pack("<Q", offset))  # 8 bytes начало
            out.write(struct.pack("<Q", length))  # 8 bytes конец 

        for chunk in data_chunks:  # сами данные последовательно
            out.write(chunk)
    pass


# ====== Enterupt ======

class PakReader:
    def __init__(self, decryptor, key, pak_path):
        self.key = key
        self.decryptor = decryptor
        self.index = {}  # hash -> (offset, length)

        self.f = open(pak_path, "rb")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)

        self._read_header()

    def _read_header(self):
        if self.mm.read(len(MAGIC)) != MAGIC:
            raise ValueError("Invalid .pak file (bad magic)")

        version = struct.unpack("<I", self.mm.read(4))[0]
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}. Current: {VERSION}")

        count = struct.unpack("<I", self.mm.read(4))[0]

        for _ in range(count):
            hname = self.mm.read(32)
            offset = struct.unpack("<Q", self.mm.read(8))[0]
            length = struct.unpack("<Q", self.mm.read(8))[0]
            self.index[hname] = (offset, length)

        self.data_start = self.mm.tell()

    def close(self):
        self.mm.close()
        self.f.close()

    def __del__(self):
        self.close()

    def __len__(self):
        return len(self.index)

    def __getitem__(self, file:str) -> io.BytesIO:
        if self.__contains__(file) == False:
            raise FileNotFoundError(f"Asset not found: {file}")

        h = hash_name(file, self.key)
        offset, length = self.index[h]
        start = self.data_start + offset
        enc = self.mm[start:start+length]

        return io.BytesIO(self.decryptor(enc, self.key))

    def __contains__(self, file:str):
        h = hash_name(file, self.key)
        if h not in self.index:
            return False
        else:
            return True
