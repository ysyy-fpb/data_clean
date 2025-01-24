import re
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import chardet

# 正则表达式
domain_pattern = re.compile(r'\b((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}\b')
url_pattern = re.compile(r'https?://(?:[a-zA-Z0-9$-_@.&+!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
ip_pattern = re.compile(r'((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)')

class DataExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("数据提取工具")
        self.root.geometry("900x600")
        self.root.minsize(600, 400)  # 最小窗口大小

        # 配置 Grid 行和列，使其自适应
        self.root.grid_rowconfigure(2, weight=1)  # 让输出框所在行可拉伸
        self.root.grid_columnconfigure((0, 1, 2), weight=1)  # 让三列自适应窗口大小

        # 文件选择框
        self.file_path_entry = tk.Entry(root, width=50)
        self.file_path_entry.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        self.file_button = tk.Button(root, text="选择文件", command=self.choose_file)
        self.file_button.grid(row=0, column=2, padx=10, pady=5, sticky="ew")

        # 开始按钮
        self.start_button = tk.Button(root, text="开始清洗", command=self.start_extraction)
        self.start_button.grid(row=1, column=0, columnspan=3, padx=10, pady=5, sticky="ew")

        # 输出框（3 列）
        self.ip_output = self.create_output_box("提取出的 IP 地址", 0)
        self.domain_output = self.create_output_box("提取出的 域名", 1)
        self.url_output = self.create_output_box("提取出的 URL", 2)

        # 显示数量的标签
        self.ip_count_label = tk.Label(root, text="IP 数量: 0")
        self.ip_count_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

        self.domain_count_label = tk.Label(root, text="域名 数量: 0")
        self.domain_count_label.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        self.url_count_label = tk.Label(root, text="URL 数量: 0")
        self.url_count_label.grid(row=3, column=2, padx=10, pady=5, sticky="w")

    def create_output_box(self, label_text, column):
        frame = tk.Frame(self.root)
        frame.grid(row=2, column=column, padx=10, pady=5, sticky="nsew")

        label = tk.Label(frame, text=label_text)
        label.pack()

        text_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
        text_box.pack(fill=tk.BOTH, expand=True)

        # 让 Frame 在窗口变化时拉伸
        self.root.grid_columnconfigure(column, weight=1)

        return text_box

    def choose_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)

    def start_extraction(self):
        file_path = self.file_path_entry.get()
        if not file_path:
            messagebox.showerror("错误", "请输入有效的文件路径")
            return

        threading.Thread(target=self.extract_data, args=(file_path,), daemon=True).start()

    def extract_data(self, file_path):
        try:
            # 检测文件编码
            with open(file_path, 'rb') as file:
                raw_data = file.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding']
                print(f"Detected encoding: {encoding}")

            # 使用检测到的编码进行读取，如果有问题再尝试其他编码
            try:
                with open(file_path, "r", encoding=encoding, errors="replace") as file:
                    data = file.readlines()
            except UnicodeDecodeError:
                # 如果用自动检测的编码还是失败，尝试其他常见编码
                with open(file_path, "r", encoding="ISO-8859-1", errors="replace") as file:
                    data = file.readlines()

            domains, urls, ips = set(), set(), set()

            for line in data:
                parts = line.strip().split(",")
                for part in parts:
                    domains.update(match.group(0) for match in domain_pattern.finditer(part))
                    urls.update(url_pattern.findall(part))
                    ips.update(match.group(0) for match in ip_pattern.finditer(part))

            # 更新输出框内容
            self.update_output(self.ip_output, "\n".join(sorted(ips)))
            self.update_output(self.domain_output, "\n".join(sorted(domains)))
            self.update_output(self.url_output, "\n".join(sorted(urls)))

            # 更新数量
            self.update_count_labels(len(ips), len(domains), len(urls))

            messagebox.showinfo("完成", "数据提取完成！")
        except Exception as e:
            messagebox.showerror("错误", f"处理文件时出错: {e}")

    def update_output(self, text_widget, content):
        text_widget.config(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, content)
        text_widget.config(state=tk.DISABLED)

    def update_count_labels(self, ip_count, domain_count, url_count):
        self.ip_count_label.config(text=f"IP 数量: {ip_count}")
        self.domain_count_label.config(text=f"域名 数量: {domain_count}")
        self.url_count_label.config(text=f"URL 数量: {url_count}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DataExtractorApp(root)
    root.mainloop()
