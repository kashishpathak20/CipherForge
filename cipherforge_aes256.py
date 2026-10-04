import base64
import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from Crypto.Cipher import AES

APP_TITLE = "CipherForge - AES-256-ECB Security Lab"
KEY_SIZE = 32
BLOCK_SIZE = 16

# CipherForge cyber-security palette
BG = "#0B1020"
PANEL = "#111827"
PANEL_2 = "#182235"
STONE = "#64748B"
STONE_DARK = "#334155"
TEXT = "#E5E7EB"
MUTED = "#94A3B8"
GRASS = "#22C55E"
GRASS_DARK = "#15803D"
DIRT = "#DC2626"
WOOD = "#F59E0B"
DIAMOND = "#38BDF8"
GOLD = "#FBBF24"
REDSTONE = "#F43F5E"
EMERALD = "#34D399"
WHITE = "#FFFFFF"


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def key_to_text(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode("ascii")


def text_to_key(key_text: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(key_text.strip().encode("ascii"))
    except Exception as exc:
        raise ValueError("Key is not valid Base64 text.") from exc
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must decode to exactly 32 bytes.")
    return key


def pkcs7_pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding]) * padding


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid ciphertext length.")
    padding = data[-1]
    if padding < 1 or padding > BLOCK_SIZE:
        raise ValueError("Invalid PKCS#7 padding.")
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid PKCS#7 padding. The key may be wrong or ciphertext was modified.")
    return data[:-padding]


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data))


def decrypt_bytes(data: bytes, key: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("ECB ciphertext must be a non-empty multiple of 16 bytes.")
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(data))


def encrypt_text(plaintext: str, key: bytes) -> str:
    if not plaintext:
        raise ValueError("Please enter a message to encrypt.")
    encrypted = encrypt_bytes(plaintext.encode("utf-8"), key)
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_text(ciphertext_b64: str, key: bytes) -> str:
    try:
        encrypted = base64.b64decode(ciphertext_b64.strip(), validate=True)
    except Exception as exc:
        raise ValueError("Ciphertext is not valid Base64.") from exc
    plaintext = decrypt_bytes(encrypted, key)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted data is not valid UTF-8 text.") from exc


def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    data = Path(input_path).read_bytes()
    Path(output_path).write_bytes(encrypt_bytes(data, key))


def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    data = Path(input_path).read_bytes()
    Path(output_path).write_bytes(decrypt_bytes(data, key))


def hex_view(data: bytes) -> str:
    if not data:
        return "(empty)"
    rows = []
    for offset in range(0, len(data), 16):
        row = data[offset:offset + 16]
        hx = " ".join(f"{b:02X}" for b in row)
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        rows.append(f"{offset:04X}   {hx:<47}   |{asc}|")
    return "\n".join(rows)


def binary_view(data: bytes) -> str:
    if not data:
        return "(empty)"
    rows = []
    for offset in range(0, len(data), 8):
        row = data[offset:offset + 8]
        rows.append(f"{offset:04X}   " + "   ".join(f"{b:08b}" for b in row))
    return "\n".join(rows)


def byte_matrix_view(data: bytes, columns: int = 8) -> str:
    if not data:
        return "(empty)"
    lines = ["      " + "  ".join(f"C{i:<2}" for i in range(columns)), "     " + "---" * columns]
    for start in range(0, len(data), columns):
        row = data[start:start + columns]
        cells = [f"{b:02X}" for b in row] + ["--"] * (columns - len(row))
        lines.append(f"R{start // columns:02d}   " + " | ".join(f"{c:^2}" for c in cells))
    return "\n".join(lines)


def zigzag_view(data: bytes, rows: int = 4) -> str:
    if not data:
        return "(empty)"
    rows = max(2, min(rows, 8))
    grid = [["  " for _ in range(len(data))] for _ in range(rows)]
    r, direction = 0, 1
    for i, b in enumerate(data):
        grid[r][i] = f"{b:02X}"
        if r == 0:
            direction = 1
        elif r == rows - 1:
            direction = -1
        r += direction
    return "\n".join(f"R{i+1}  " + " ".join(row) for i, row in enumerate(grid))


def ecb_block_matrix(data: bytes) -> str:
    if not data:
        return "(empty)"
    lines = [
        "AES-256-ECB — 16-BYTE BLOCK MATRIX",
        "",
        "BLOCK | " + " ".join(f"{i:02X}" for i in range(16)),
        "------+" + "---" * 16,
    ]
    for n, start in enumerate(range(0, len(data), BLOCK_SIZE), start=1):
        block = data[start:start + BLOCK_SIZE]
        lines.append(f"{n:5d} | " + " ".join(f"{b:02X}" for b in block))
    return "\n".join(lines)


def package_map(data: bytes) -> str:
    blocks = len(data) // BLOCK_SIZE
    return "\n".join([
        "+--------------------------------------------------+",
        "|              AES-256-ECB DATA MAP               |",
        "+--------------------------------------------------+",
        f"| Key size       : {KEY_SIZE} bytes / 256 bits       |",
        f"| Block size     : {BLOCK_SIZE} bytes                   |",
        f"| Ciphertext     : {len(data)} bytes                  |",
        f"| AES blocks     : {blocks:<3}                              |",
        "| Padding        : PKCS#7                         |",
        "+--------------------------------------------------+",
        "",
        "PLAINTEXT",
        "   ↓",
        "PKCS#7 PADDING",
        "   ↓",
        "AES-256-ECB",
        "   ↓",
        "RAW CIPHERTEXT",
        "   ↓",
        "BASE64 DISPLAY",
        "",
        "IMPORTANT: ECB does not provide authentication or integrity.",
        "It is included here for educational/demo purposes.",
    ])


class PixelButton(tk.Button):
    def __init__(self, master, text, command, bg=STONE_DARK, width=16, **kwargs):
        super().__init__(
            master, text=text, command=command,
            bg=bg, fg=WHITE, activebackground=bg,
            activeforeground=WHITE, relief="raised", bd=3,
            highlightthickness=0, font=("DejaVu Sans Mono", 10, "bold"),
            cursor="hand2", width=width, padx=8, pady=7, **kwargs
        )


class PixelPanel(tk.Frame):
    def __init__(self, master, title=None, **kwargs):
        super().__init__(master, bg=PANEL, highlightbackground=STONE_DARK, highlightthickness=2, **kwargs)
        if title:
            tk.Label(self, text=title, bg=PANEL, fg=GOLD,
                     font=("DejaVu Sans Mono", 11, "bold")).pack(anchor="w", padx=12, pady=(9, 6))


class CryptoApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1250x900")
        self.root.minsize(950, 700)
        self.root.configure(bg=BG)
        self.key_var = tk.StringVar()
        self.status_var = tk.StringVar()
        self.info_var = tk.StringVar(value="No ciphertext loaded")
        self.key_visible = False
        self._build_ui()
        self.set_status("READY • Generate or paste a 256-bit AES key.", "info")

    def _build_ui(self):
        # Cyber-grid background canvas.
        bg_canvas = tk.Canvas(self.root, bg=BG, highlightthickness=0)
        bg_canvas.place(relx=0, rely=0, relwidth=1, relheight=1)

        def draw_bg(event=None):
            bg_canvas.delete("all")
            w, h = max(1, bg_canvas.winfo_width()), max(1, bg_canvas.winfo_height())
            size = 32
            cols, rows = w // size + 2, h // size + 2
            for r in range(rows):
                for c in range(cols):
                    x, y = c * size, r * size
                    if r < max(1, int(rows * 0.42)):
                        base, accent = "#0F172A", "#172554"
                    else:
                        base, accent = "#111827", "#1E293B"
                    bg_canvas.create_rectangle(x, y, x + size, y + size, fill=base, outline="#172033")
                    if (r * 11 + c * 7) % 6 == 0:
                        bg_canvas.create_rectangle(x + 5, y + 5, x + 10, y + 10, fill=accent, outline="")
                    if (r * 5 + c * 13) % 9 == 0:
                        bg_canvas.create_rectangle(x + 21, y + 21, x + 27, y + 27, fill="#0B1220", outline="")
            horizon = int(h * 0.42)
            bg_canvas.create_rectangle(0, horizon, w, horizon + 2, fill="#1E3A5F", outline="")
            bg_canvas.create_rectangle(0, horizon + 2, w, horizon + 3, fill=DIAMOND, outline="")
            for fx, fy, color in [(0.08, 0.24, DIAMOND), (0.22, 0.68, GOLD), (0.82, 0.28, REDSTONE), (0.91, 0.76, EMERALD)]:
                x, y = int(w * fx), int(h * fy)
                bg_canvas.create_rectangle(x, y, x + 10, y + 10, fill=color, outline="#101010")
                bg_canvas.create_rectangle(x + 10, y + 4, x + 16, y + 14, fill=color, outline="#101010")

        bg_canvas.bind("<Configure>", draw_bg)

        header = tk.Frame(self.root, bg="#070B14", height=118)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Frame(header, bg=DIAMOND, height=3).pack(fill="x")
        h = tk.Frame(header, bg="#080808")
        h.pack(fill="both", expand=True, padx=22)
        tk.Label(h, text="◈  CIPHERFORGE  ◈", bg="#070B14", fg=DIAMOND,
                 font=("DejaVu Sans Mono", 24, "bold")).pack(anchor="w", pady=(11, 1))
        tk.Label(h, text="AES-256-ECB  •  CRYPTOGRAPHY WORKBENCH  •  DATA INSPECTION",
                 bg="#070B14", fg=MUTED, font=("DejaVu Sans Mono", 10, "bold")).pack(anchor="w")

        # Scrollable content.
        wrap = tk.Frame(self.root, bg=BG)
        wrap.pack(fill="both", expand=True, padx=12, pady=10)
        canvas = tk.Canvas(wrap, bg=BG, highlightthickness=0, bd=0)
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        content = tk.Frame(canvas, bg=BG)
        window_id = canvas.create_window((0, 0), window=content, anchor="nw")

        def update_region(_=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def resize_width(event):
            canvas.itemconfigure(window_id, width=event.width)
        def wheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        content.bind("<Configure>", update_region)
        canvas.bind("<Configure>", resize_width)
        canvas.bind_all("<MouseWheel>", wheel)

        self._build_key_section(content)
        self._build_text_section(content)
        self._build_visualizer(content)
        self._build_file_section(content)

        status = tk.Frame(self.root, bg="#070B14", highlightbackground=STONE_DARK, highlightthickness=1)
        status.pack(fill="x", padx=12, pady=(0, 9))
        tk.Label(status, text="SYSTEM STATUS", bg="#070B14", fg=GOLD,
                 font=("Courier New", 9, "bold")).pack(side="left", padx=10, pady=8)
        self.status_label = tk.Label(status, textvariable=self.status_var, bg="#070B14",
                                     fg=EMERALD, font=("Courier New", 9, "bold"))
        self.status_label.pack(side="left", padx=4, pady=8)
        tk.Label(self.root, text="⚠ SECURITY NOTE: AES-ECB provides no authentication/integrity. Use authenticated encryption for production.",
                 bg=BG, fg=REDSTONE, font=("Courier New", 9, "bold")).pack(anchor="w", padx=18, pady=(0, 9))

    def _build_key_section(self, parent):
        panel = PixelPanel(parent, "01  //  SECRET KEY  ·  AES-256")
        panel.pack(fill="x", pady=(0, 9))
        row = tk.Frame(panel, bg=PANEL)
        row.pack(fill="x", padx=10, pady=(2, 4))
        self.key_entry = tk.Entry(row, textvariable=self.key_var, show="*", bg="#080808", fg=DIAMOND,
                                  insertbackground=WHITE, relief="sunken", bd=3, font=("Courier New", 10, "bold"))
        self.key_entry.pack(side="left", fill="x", expand=True, padx=(0, 6), ipady=6)
        PixelButton(row, "◆ GENERATE", self.generate_key, GRASS_DARK, 14).pack(side="left", padx=3)
        PixelButton(row, "◉ SHOW/HIDE", self.toggle_key_visibility, STONE_DARK, 14).pack(side="left", padx=3)
        PixelButton(row, "▣ COPY KEY", self.copy_key, DIRT, 12).pack(side="left", padx=3)
        tk.Label(panel, text="32 bytes / 256 bits  •  Base64-safe display  •  ECB uses 16-byte blocks",
                 bg=PANEL, fg=MUTED, font=("Courier New", 8)).pack(anchor="w", padx=12, pady=(0, 8))

    def _text_box(self, master, height=12):
        return ScrolledText(master, height=height, wrap=tk.WORD, bg="#090909", fg=TEXT,
                            insertbackground=WHITE, selectbackground=GRASS_DARK,
                            relief="sunken", bd=3, highlightthickness=1,
                            highlightbackground=STONE_DARK, font=("Courier New", 10),
                            padx=10, pady=8)

    def _build_text_section(self, parent):
        outer = tk.Frame(parent, bg="#111111")
        outer.pack(fill="both", expand=True, pady=(0, 9))
        left = PixelPanel(outer, "02  //  PLAINTEXT / INPUT")
        right = PixelPanel(outer, "03  //  CIPHERTEXT / BASE64")
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.plaintext_box = self._text_box(left, 14)
        self.plaintext_box.pack(fill="both", expand=True, padx=10, pady=(2, 7))
        self.ciphertext_box = self._text_box(right, 14)
        self.ciphertext_box.pack(fill="both", expand=True, padx=10, pady=(2, 7))
        lb = tk.Frame(left, bg=PANEL)
        lb.pack(fill="x", padx=10, pady=(0, 9))
        PixelButton(lb, "▶ ENCRYPT", self.encrypt, GRASS_DARK, 16).pack(side="left", padx=(0, 5))
        PixelButton(lb, "✕ CLEAR", self.clear_text, DIRT, 12).pack(side="left", padx=5)
        rb = tk.Frame(right, bg=PANEL)
        rb.pack(fill="x", padx=10, pady=(0, 9))
        PixelButton(rb, "DECRYPT ◀", self.decrypt, "#4F46E5", 16).pack(side="left", padx=(0, 5))
        PixelButton(rb, "▣ COPY", self.copy_ciphertext, STONE_DARK, 12).pack(side="left", padx=5)

    def _build_visualizer(self, parent):
        panel = PixelPanel(parent, "04  //  CIPHERTEXT INTELLIGENCE")
        panel.pack(fill="both", expand=True, pady=(0, 9))
        top = tk.Frame(panel, bg=PANEL)
        top.pack(fill="x", padx=10, pady=(0, 4))
        tk.Label(top, textvariable=self.info_var, bg=PANEL, fg=EMERALD,
                 font=("Courier New", 9, "bold")).pack(side="left")
        tk.Label(top, text="RAW BLOCK DATA", bg=PANEL, fg=MUTED,
                 font=("Courier New", 9)).pack(side="right")
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("CipherForge.TNotebook", background=BG, borderwidth=0)
        style.configure("CipherForge.TNotebook.Tab", background=STONE_DARK, foreground=TEXT,
                        padding=(14, 8), font=("Courier New", 9, "bold"))
        style.map("CipherForge.TNotebook.Tab", background=[("selected", GRASS_DARK)], foreground=[("selected", WHITE)])
        nb = ttk.Notebook(panel, style="CipherForge.TNotebook")
        nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.views = {}
        for title, key in [("Base64", "Base64"), ("Hex Dump", "Hex"), ("Binary", "Binary"),
                           ("Zig-Zag", "ZigZag"), ("Matrix", "Matrix"), ("Package Map", "Map")]:
            tab = tk.Frame(nb, bg="#080808")
            nb.add(tab, text=title)
            box = ScrolledText(tab, wrap=tk.NONE, bg="#070707", fg=TEXT, insertbackground=WHITE,
                               selectbackground=GRASS_DARK, relief="flat", bd=0,
                               font=("Courier New", 9), padx=10, pady=8)
            box.pack(fill="both", expand=True, padx=8, pady=8)
            self.views[key] = box

    def _build_file_section(self, parent):
        panel = PixelPanel(parent, "05  //  FILE ENCRYPTION / DECRYPTION")
        panel.pack(fill="x", pady=(0, 9))
        row = tk.Frame(panel, bg=PANEL)
        row.pack(fill="x", padx=10, pady=(2, 10))
        PixelButton(row, "⇧ ENCRYPT FILE", self.encrypt_file_ui, GRASS_DARK, 17).pack(side="left", padx=(0, 6))
        PixelButton(row, "⇩ DECRYPT FILE", self.decrypt_file_ui, "#4F46E5", 17).pack(side="left", padx=6)
        tk.Label(row, text="CipherForge demo: try TXT, PNG or PDF files.", bg=PANEL, fg=MUTED,
                 font=("Courier New", 9)).pack(side="left", padx=16)

    def set_status(self, message, level="info"):
        self.status_var.set(message)
        self.status_label.configure(fg={"success": EMERALD, "error": REDSTONE, "info": DIAMOND}.get(level, DIAMOND))

    def get_key(self):
        text = self.key_var.get().strip()
        if not text:
            raise ValueError("Please generate or enter a secret key first.")
        return text_to_key(text)

    def generate_key(self):
        self.key_var.set(key_to_text(generate_key()))
        self.set_status("NEW AES-256 KEY GENERATED • 256 bits ready.", "success")

    def toggle_key_visibility(self):
        self.key_visible = not self.key_visible
        self.key_entry.configure(show="" if self.key_visible else "*")

    def copy_key(self):
        value = self.key_var.get().strip()
        if not value:
            self.set_status("NO KEY AVAILABLE TO COPY.", "error")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.set_status("KEY COPIED • Keep it secret.", "success")

    def copy_ciphertext(self):
        value = self.ciphertext_box.get("1.0", tk.END).strip()
        if not value:
            self.set_status("NO CIPHERTEXT AVAILABLE TO COPY.", "error")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.set_status("CIPHERTEXT COPIED.", "success")

    def encrypt(self):
        try:
            key = self.get_key()
            plaintext = self.plaintext_box.get("1.0", tk.END).rstrip("\n")
            ciphertext = encrypt_text(plaintext, key)
            self.ciphertext_box.delete("1.0", tk.END)
            self.ciphertext_box.insert("1.0", ciphertext)
            self.update_visualizations(ciphertext)
            self.set_status("ENCRYPTION SUCCESSFUL • AES-256-ECB ciphertext generated.", "success")
        except Exception as exc:
            self.set_status(f"ERROR • {exc}", "error")
            messagebox.showerror("Encryption Error", str(exc))

    def decrypt(self):
        try:
            key = self.get_key()
            ciphertext = self.ciphertext_box.get("1.0", tk.END).strip()
            plaintext = decrypt_text(ciphertext, key)
            self.plaintext_box.delete("1.0", tk.END)
            self.plaintext_box.insert("1.0", plaintext)
            self.update_visualizations(ciphertext)
            self.set_status("DECRYPTION SUCCESSFUL • Padding verified.", "success")
        except Exception as exc:
            self.set_status(f"ERROR • {exc}", "error")
            messagebox.showerror("Decryption Error", str(exc))

    def clear_text(self):
        self.plaintext_box.delete("1.0", tk.END)
        self.ciphertext_box.delete("1.0", tk.END)
        self.info_var.set("No ciphertext loaded")
        for box in self.views.values():
            box.delete("1.0", tk.END)
        self.set_status("TEXT FIELDS CLEARED.", "info")

    def update_visualizations(self, ciphertext_b64):
        data = base64.b64decode(ciphertext_b64.strip(), validate=True)
        self.info_var.set(f"CIPHERTEXT: {len(data)} bytes  •  BLOCK: {BLOCK_SIZE} bytes  •  BLOCKS: {len(data) // BLOCK_SIZE}")
        self.views["Base64"].delete("1.0", tk.END); self.views["Base64"].insert("1.0", ciphertext_b64.strip())
        self.views["Hex"].delete("1.0", tk.END); self.views["Hex"].insert("1.0", hex_view(data))
        self.views["Binary"].delete("1.0", tk.END); self.views["Binary"].insert("1.0", binary_view(data))
        self.views["ZigZag"].delete("1.0", tk.END); self.views["ZigZag"].insert("1.0", zigzag_view(data))
        self.views["Matrix"].delete("1.0", tk.END); self.views["Matrix"].insert("1.0", ecb_block_matrix(data) + "\n\n" + byte_matrix_view(data))
        self.views["Map"].delete("1.0", tk.END); self.views["Map"].insert("1.0", package_map(data))

    def encrypt_file_ui(self):
        try:
            key = self.get_key()
            input_path = filedialog.askopenfilename(title="Select a file to encrypt")
            if not input_path:
                return
            output_path = filedialog.asksaveasfilename(
                title="Save encrypted file", initialfile=Path(input_path).name + ".enc",
                defaultextension=".enc", filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            if not output_path:
                return
            encrypt_file(input_path, output_path, key)
            self.set_status(f"FILE ENCRYPTED • {Path(output_path).name}", "success")
            messagebox.showinfo("CipherForge", "File encrypted successfully.")
        except Exception as exc:
            self.set_status(f"ERROR • {exc}", "error")
            messagebox.showerror("File Encryption Error", str(exc))

    def decrypt_file_ui(self):
        try:
            key = self.get_key()
            input_path = filedialog.askopenfilename(
                title="Select an encrypted .enc file",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            if not input_path:
                return
            output_path = filedialog.asksaveasfilename(
                title="Save decrypted file", initialfile=Path(input_path).stem
            )
            if not output_path:
                return
            decrypt_file(input_path, output_path, key)
            self.set_status(f"FILE DECRYPTED • {Path(output_path).name}", "success")
            messagebox.showinfo("CipherForge", "File decrypted successfully.")
        except Exception as exc:
            self.set_status(f"ERROR • {exc}", "error")
            messagebox.showerror("File Decryption Error", str(exc))


def main():
    root = tk.Tk()
    CryptoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
