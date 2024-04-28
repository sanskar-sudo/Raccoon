from tkinter import *
from tkinter import scrolledtext, messagebox, Toplevel, ttk
from scapy.all import AsyncSniffer, TCP, UDP, ARP, ICMP, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, IP
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinter.colorchooser import askcolor
import threading

print ("Raccoon is up and Running.....")
class PacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Raccoon")
        self.root.geometry("1000x600")

        # Initialize protocol filter variables
        self.filter_tcp = BooleanVar(value=True)
        self.filter_udp = BooleanVar(value=True)
        self.filter_arp = BooleanVar(value=True)
        self.filter_icmp = BooleanVar(value=True)
        self.filter_ip = ""

        self.create_widgets()

        # Initialize Matplotlib figure and axes for packet traffic visualization
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(side=RIGHT, fill=BOTH, expand=True)

        # Variables to store packet counts
        self.tcp_count = 0
        self.udp_count = 0
        self.arp_count = 0
        self.icmp_count = 0

        # Plot initial empty graph
        self.plot_graph()

    def create_widgets(self):
        # Frame to contain the text area and its settings
        self.text_frame = Frame(self.root)
        self.text_frame.pack(side=LEFT, expand=True, fill=BOTH, padx=5, pady=5)

        # Scrolled text widget to display captured packets
        self.text_area = scrolledtext.ScrolledText(self.text_frame, wrap=WORD, width=80, height=30, borderwidth=2, relief="solid")
        self.text_area.pack(expand=True, fill=BOTH)

        # Button to start/stop packet sniffing
        self.start_stop_button = ttk.Button(self.root, text="Start Sniffing", command=self.toggle_sniffing, style='C.TButton')
        self.start_stop_button.pack(pady=10)

        # Checkbox to enable/disable packet filtering
        self.filter_var = IntVar()
        self.filter_var.set(0)
        self.filter_checkbox = ttk.Checkbutton(self.root, text="Enable Filtering", variable=self.filter_var, style='C.TCheckbutton')
        self.filter_checkbox.pack()

        # Entry widget to specify filter criteria
        self.filter_entry = Entry(self.root, width=50, font=("Arial", 12), borderwidth=2, relief="solid")
        self.filter_entry.insert(0, "")
        self.filter_entry.pack(pady=5)

        # Submit button for applying filter
        self.submit_button = ttk.Button(self.root, text="Submit", command=self.apply_filter, style='C.TButton')
        self.submit_button.pack(pady=5)

        # Frame to contain protocol filter buttons
        self.protocol_frame = Frame(self.root)
        self.protocol_frame.pack()

        # Protocol filter buttons using ttk.Checkbutton for modern styling
        self.tcp_button = ttk.Checkbutton(self.protocol_frame, text="TCP", variable=self.filter_tcp, style='C.TCheckbutton')
        self.tcp_button.pack(side=LEFT)
        self.udp_button = ttk.Checkbutton(self.protocol_frame, text="UDP", variable=self.filter_udp, style='C.TCheckbutton')
        self.udp_button.pack(side=LEFT)
        self.arp_button = ttk.Checkbutton(self.protocol_frame, text="ARP", variable=self.filter_arp, style='C.TCheckbutton')
        self.arp_button.pack(side=LEFT)
        self.icmp_button = ttk.Checkbutton(self.protocol_frame, text="ICMP", variable=self.filter_icmp, style='C.TCheckbutton')
        self.icmp_button.pack(side=LEFT)

        # Add a dropdown menu for selecting text area background color
        self.color_label_bg = Label(self.root, text="Select Text Area Background Color:", font=("Arial", 12))
        self.color_label_bg.pack(pady=5)

        self.color_button_bg = Button(self.root, text="Choose Background Color", command=self.choose_bg_color)
        self.color_button_bg.pack(pady=5)

        # Add a dropdown menu for selecting text area foreground (text) color
        self.color_label_fg = Label(self.root, text="Select Text Area Foreground Color:", font=("Arial", 12))
        self.color_label_fg.pack(pady=5)

        self.color_button_fg = Button(self.root, text="Choose Foreground Color", command=self.choose_fg_color)
        self.color_button_fg.pack(pady=5)

        # Default text area background color
        self.text_bg_color = "white"  # Default color

        # Default text area foreground (text) color
        self.text_fg_color = "black"  # Default color

        # Define custom styles
        style = ttk.Style()
        style.configure('C.TButton', foreground='blue', font=('Arial', 12))
        style.configure('C.TCheckbutton', font=('Arial', 12))

        # Bind window resize event
        self.root.bind("<Configure>", self.on_window_resize)

        # Bind double-click event to show packet details
        self.text_area.bind("<Double-Button-1>", self.show_packet_details)

    def toggle_sniffing(self):
        if self.start_stop_button.cget("text") == "Start Sniffing":
            self.start_sniffing()
        else:
            self.stop_sniffing()

    def on_window_resize(self, event):
        # Adjust text area size when window is resized
        self.text_area.config(width=self.root.winfo_width() // 10, height=self.root.winfo_height() // 20)

    def start_sniffing(self):
        try:
            self.filter = self.filter_entry.get() if self.filter_var.get() else None
            self.start_stop_button.config(text="Stop Sniffing")
            # Start the sniffing process in a separate thread
            self.sniffing_thread = threading.Thread(target=self.start_sniffing_thread, daemon=True)
            self.sniffing_thread.start()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def start_sniffing_thread(self):
        try:
            self.sniffer = AsyncSniffer(prn=self.process_packet, filter=self.filter)
            self.sniffer.start()
        except Exception as e:
            print("An error occurred while starting sniffing thread:", str(e))

    def stop_sniffing(self):
        try:
            if hasattr(self, 'sniffer'):
                self.sniffer.stop()
            self.start_stop_button.config(text="Start Sniffing")
        except Exception as e:
            print("An error occurred while stopping sniffing:", str(e))

    def process_packet(self, packet):
        try:
            if self.should_display_packet(packet):
                if TCP in packet:
                    self.tcp_count += 1
                elif UDP in packet:
                    self.udp_count += 1
                elif ARP in packet:
                    self.arp_count += 1
                elif ICMP in packet or ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
                    self.icmp_count += 1
                self.plot_graph()
                packet_text = str(packet) + "\n"
                self.text_area.insert(END, packet_text)
                self.text_area.see(END)  # Scroll to the bottom
        except Exception as e:
            print("An error occurred while processing packet:", str(e))

    def should_display_packet(self, packet):
        if not self.filter_tcp.get() and TCP in packet:
            return False
        if not self.filter_udp.get() and UDP in packet:
            return False
        if not self.filter_arp.get() and ARP in packet:
            return False
        if not self.filter_icmp.get() and (ICMP in packet or ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet):
            return False
        if self.filter_ip:
            ip_src = packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else None
            ip_dst = packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else None
            if ip_src != self.filter_ip and ip_dst != self.filter_ip:
                return False
        return True

    def apply_filter(self):
        self.filter_ip = self.filter_entry.get()
        self.filter_entry.delete(0, END)
        self.filter_entry.insert(0, f"Filtering by IP: {self.filter_ip}")

    def show_packet_details(self, event):
        index = self.text_area.index("@%s,%s" % (event.x, event.y))
        line_number = int(index.split(".")[0])
        line_text = self.text_area.get(f"{line_number}.0", f"{line_number + 1}.0")
        packet = line_text.strip()
        if packet:
            details_window = Toplevel(self.root)
            details_window.title("Packet Details")

            details_text = scrolledtext.ScrolledText(details_window, wrap=WORD, width=80, height=20)
            details_text.pack(expand=True, fill=BOTH)

            details_text.tag_config("header", foreground="blue", font=("Arial", 12, "bold"))
            details_text.tag_config("field", font=("Arial", 10))
            details_text.tag_config("value", font=("Arial", 10))

            details_text.insert(END, "Packet Details\n\n", "header")
            details_text.insert(END, "Ethernet Header:\n", "field")
            details_text.insert(END, packet + "\n\n", "value")
            details_text.insert(END, "IP Header:\n", "field")
            details_text.insert(END, packet + "\n\n", "value")
            details_text.insert(END, "TCP/UDP/ICMP/ARP Header:\n", "field")
            details_text.insert(END, packet + "\n\n", "value")
            details_text.insert(END, "Payload:\n", "field")
            details_text.insert(END, packet, "value")

            details_window.mainloop()

    def plot_graph(self):
        protocols = ['TCP', 'UDP', 'ARP', 'ICMP']
        counts = [self.tcp_count, self.udp_count, self.arp_count, self.icmp_count]
        colors = ['blue', 'green', 'purple', 'orange']

        self.ax.clear()
        self.ax.bar(protocols, counts, color=colors)
        self.ax.set_xlabel('Protocol')
        self.ax.set_ylabel('Packet Count')
        self.ax.set_title('Live Packet Traffic')
        self.canvas.draw()

    def choose_bg_color(self):
        color = askcolor(title="Choose Text Area Background Color")
        if color[1]:  # If a color is selected
            self.text_bg_color = color[1]
            self.text_area.configure(bg=self.text_bg_color)

    def choose_fg_color(self):
        color = askcolor(title="Choose Text Area Foreground (Text) Color")
        if color[1]:  # If a color is selected
            self.text_fg_color = color[1]
            self.text_area.configure(fg=self.text_fg_color)


if __name__ == "__main__":
    root = Tk()
    app = PacketSniffer(root)
    root.mainloop()
