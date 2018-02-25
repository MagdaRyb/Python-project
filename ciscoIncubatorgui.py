try:
    import Tkinter as tk
    import Tkinter, Tkconstants, tkFileDialog
    import tkMessageBox
    import sys
    import json
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from ciscoIncubatorProjectGroup11 import generate_network_topology, \
        resultCollectionMethod, project_main_executor, check_iprange_and_retrieve_available_ips
except ImportError as tk_err:
    print 'Failed to start the GUI, please make sure you install [tkinter]', tk_err
    sys.exit(1)


class DeviceViewPane(tk.Frame):

    def __init__(self, device_data, devices_data, name, master=None):
        tk.Frame.__init__(self, master)
        self.rowconfigure(4, {'minsize': 200})
        self.columnconfigure(2, {'minsize': 200})
        self.configure(relief=tk.GROOVE)
        vscrollbar = tk.Scrollbar(self, orient=tk.VERTICAL)
        hscrollbar = tk.Scrollbar(self, orient=tk.HORIZONTAL)
        c = tk.Canvas(self, bg='white',  width=1200, height=800,
                      yscrollcommand=vscrollbar.set, xscrollcommand=hscrollbar.set)

        vscrollbar.config(command=c.yview)
        vscrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        hscrollbar.config(command=c.xview)
        hscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        c.pack()

        device_main_frame = tk.Frame(c)

        device_c = tk.Canvas(device_main_frame, bg='seashell', width=500, height=800)
        device_c.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        self.device_info_view = tk.Frame(device_c, background="seashell")
        self.device_info_view.pack(fill="both", expand=True)
        self.device_module_view = tk.Frame(device_c, background="mint cream")
        self.device_module_view.pack(fill="both", expand=True)
        self.device_interface_view = tk.Frame(device_main_frame, background="lavender")
        self.device_interface_view.pack(side="left", fill="both", expand=True)
        self.results_label_holders("Harware: ", device_data["device_hardware_os_information"]["hardware_info"],
                                   self.device_info_view, 2, 0)
        self.results_label_holders("OS information: ", device_data["device_hardware_os_information"]["os_info"],
                                   self.device_info_view, 3, 0)
        self.results_label_holders("Management IP: ", device_data["device_hardware_os_information"]["ip"],
                                   self.device_info_view, 4, 0)
        # self.results_label_holders("Manager Username: ", device_data["device_hardware_os_information"]["user"],
        #                             self.device_info_view, 5, 0)
        self.results_label_holders("Manager Password: ", device_data["device_hardware_os_information"]["password"],
                                   self.device_info_view, 6, 0)

        static_label = tk.Label(self.device_interface_view, text="INTERFACES INFORMATION",
                                background="lavender", font=("Courier", 18, "bold"))
        static_label.grid(row=0, column=0, columnspan=2, sticky=tk.N + tk.S + tk.E + tk.W)
        static_label = tk.Label(self.device_info_view, text="HARDWARE AND OS INFORMATION",
                                background="seashell", font=("Courier", 18, "bold"))
        static_label.grid(row=0, column=0, columnspan=2, sticky=tk.N + tk.S + tk.E + tk.W)
        static_label = tk.Label(self.device_module_view, text="MODULES INFORMATION",
                                background="mint cream", font=("Courier", 18, "bold"))
        static_label.grid(row=1, column=0, columnspan=2, sticky=tk.N + tk.S + tk.E + tk.W)
        self.separator_label(self.device_module_view, 0, 0, 'gainsboro')
        self.separator_label(self.device_info_view, 1, 0, 'gainsboro')
        i = 1
        for interface in device_data["device_interfaces_information"]:
            self.separator_label(self.device_interface_view, i, 0, "gainsboro")
            interface_data = device_data["device_interfaces_information"][interface]
            self.results_label_holders("Interface Name: ", interface, self.device_interface_view, i+1, 0)
            self.check_has_key("Internet Address: ", interface_data, "Internet address", self.device_interface_view, i+2, 0)
            self.check_has_key("Hardware: ", interface_data, "Hardware", self.device_interface_view, i+3, 0)
            self.check_has_key("Physical Address: ", interface_data, "address", self.device_interface_view, i+4, 0)
            self.check_has_key("Media Type: ", interface_data, "media type", self.device_interface_view, i+5, 0)
            self.check_has_key("State: ", interface_data, interface, self.device_interface_view, i+6, 0)
            self.check_has_key("Line protocol: ", interface_data, "line protocol", self.device_interface_view, i+7, 0)
            i = i + 8

        i = 2

        for module in device_data["device_hardware_os_information"]["modules_info"]:
            self.separator_label(self.device_module_view, i, 0, "gainsboro")
            module_data = device_data["device_hardware_os_information"]["modules_info"][module]
            module_can = tk.Canvas(self.device_module_view, bg='mint cream', width=300,
                                   height=380, scrollregion=(0, 0, 1200, 2000))
            module_can.grid(row=i+1, column=0, columnspan=2, sticky=tk.N+tk.S+tk.E+tk.W)
            details_c = tk.Canvas(module_can, bg='mint cream', width=250, height=200)
            details_c.pack(side="left", fill="both", expand=True)
            static_label = tk.Label(details_c, text="MODULE",
                                    background="mint cream", font=("Courier", 16, "bold"))
            static_label.grid(row=0, column=0, columnspan=2, sticky=tk.N + tk.S + tk.E + tk.W)
            self.results_label_holders("Module Name: ", module, details_c, 1, 0)
            self.check_has_key("Serial Number: ", module_data, "SN", details_c, 2, 0)
            self.check_has_key("Description: : ", module_data, "description", details_c, 3, 0)
            if "end_of_life_or_end_of_service" in module_data:
                module_eox_data = module_data["end_of_life_or_end_of_service"]
            else:
                module_eox_data = None
            eox_c = tk.Canvas(module_can, bg='mint cream', width=250, height=200)
            eox_c.pack(side="left", fill="both", expand=True)
            static_label = tk.Label(eox_c, text="EoL/EoS DATA",
                                    background="mint cream", font=("Courier", 16, "bold"))
            static_label.grid(row=0, column=0, columnspan=2, sticky=tk.N + tk.S + tk.E + tk.W)
            if module_eox_data is not None:
                if "EOXRecord" in module_eox_data:
                    if module_eox_data['EOXRecord'][0] is not None:
                        self.check_has_key("EoL Product ID: ", module_eox_data['EOXRecord'][0],
                                           "EOLProductID", eox_c, 1, 0)
                        self.check_has_key("EoL Product ID: ", module_eox_data['EOXRecord'][0],
                                           "EOLProductID", eox_c, 1, 0)

                        self.check_has_key("Product Builletin: ", module_eox_data["EOXRecord"][0],
                                           "LinkToProductBulletinURL", details_c, 4, 0)
                        self.check_has_key("Product Full Description: ", module_eox_data['EOXRecord'][0],
                                           "ProductIDDescription", details_c, 5, 0)
                        self.check_has_key_eox("End of Failure Analysis: ",
                                               module_eox_data['EOXRecord'][0],
                                               "EndOfRoutineFailureAnalysisDate", eox_c, 2, 0)
                        self.check_has_key_eox("End of Software Maintenance Releases: ",
                                               module_eox_data['EOXRecord'][0],
                                               "EndOfSWMaintenanceReleases", eox_c, 3, 0)
                        self.check_has_key_eox("End of Sale: ",
                                               module_eox_data['EOXRecord'][0],
                                               "EndOfSaleDate", eox_c, 4, 0)
                        self.check_has_key_eox("End of Security Vulnerability Support: ",
                                               module_eox_data['EOXRecord'][0],
                                               "EndOfSecurityVulSupportDate", eox_c, 5, 0)
                        self.check_has_key_eox("End of Service Contract Renewal: ",
                                               module_eox_data['EOXRecord'][0],
                                               "EndOfServiceContractRenewal", eox_c, 6, 0)
                        self.check_has_key_eox("Last date of support: ",
                                               module_eox_data['EOXRecord'][0], "LastDateOfSupport", eox_c, 7, 0)
            i = i + 2
            device_main_frame.update()
            c.config(scrollregion=c.bbox("all"))
            c.create_window(0, 0, window=device_main_frame, anchor='nw')

    def check_has_key_eox(self, label, data, key, container, row, col):
        if key in data:
            data = data[key]
            self.check_has_key(label, data, "value", container, row, col)

    def check_has_key(self, label, data, key, container, row, col):
        if key in data:
            self.results_label_holders(label, data[key], container, row, col)
        else:
            self.results_label_holders(label, "", container, row, col)

    @staticmethod
    def separator_label(container, row, col, color):
        static_label = tk.Label(container, text="", background=color)
        static_label.grid(row=row, column=col, columnspan=2, sticky=tk.N+tk.S+tk.E+tk.W)

    def results_label_holders(self, label, value,  container, row_pos, colon_pos):
        static_label = tk.Label(container, text=label,  background=container.cget("background"),
                                font=("Courier", 14, "bold"))
        static_label.grid(row=row_pos, padx=5, column=colon_pos, sticky=tk.W)

        if label == "Product Builletin: ":
            result_label = tk.Message(container, text=value, fg="blue", cursor="hand2")
            result_label.bind("<Button-1>", lambda e, val=value: self.open_link(value))
        elif label == "Product Full Description: " or label == "OS information: ":
            result_label = tk.Message(container, text=value, background=container.cget("background"))
        else:
            result_label = tk.Label(container, text=value, background=container.cget("background"))
        if not value or value is None or value == str(0):
            result_label.grid(row=row_pos, padx=5, column=colon_pos + 1, sticky=tk.N + tk.S + tk.E + tk.W)
            result_label.configure(background='red')
        else:
            result_label.grid(row=row_pos, padx=5, column=colon_pos + 1, sticky=tk.W)

    @staticmethod
    def open_link(value):
        try:
            import webbrowser
            if tkMessageBox.askyesno("Warning", "Do you wish to open %s in a browser?" % value):
                webbrowser.open_new(r"%s" % value)
        except ImportError as e:
            tkMessageBox.showerror("An Error occurred", "Please make sure to have [webbrowser] module installed "
                                                        "for your python environment", e)


class DevicesViewPane(tk.Frame):
    buttons = {}
    is_topology_displayed = False

    def __init__(self, devices_data, master=None):
        tk.Frame.__init__(self, master)
        button_frame = tk.Frame(self, background="#bfbfbf")
        main_container = tk.Frame(self)
        button_frame.pack(side="top" , fill="x", expand=False)
        main_container.pack(side="top", fill="both", expand=True)
        device_to = None
        first_button = ''
        for device in devices_data:
            device_view = DeviceViewPane(devices_data[device], devices_data, device, master=master)
            device_view.place(in_=main_container, x=0, y=0, relwidth=1, relheight=1)
            self.buttons[device] = tk.Button(button_frame, background="#bfbfbf",
                                             text=device, highlightbackground="#bfbfbf",
                                             command=lambda d=device, dev=device_view: self.show(d, dev))
            self.buttons[device].pack(side="left")
            if device_to is None:
                device_to = device_view
                first_button = device
        self.topology_view = tk.Frame(master=master)
        self.topology_view.place(in_=main_container, x=0, y=0, relwidth=1, relheight=1)

        self.topology = tk.Button(button_frame, text='Display Topology',
                                  background="#bfbfbf", highlightbackground="#bfbfbf",
                                  command=lambda d=devices_data: self.display_topology(d))
        self.topology.pack(side="left")
        self.buttons["topology"] = self.topology
        if device_to is not None:
            device_to.lift()
            self.buttons[first_button].configure(background="cornflower blue", highlightbackground='cornflower blue')

    def display_topology(self, all_devices_data):
        self.show("topology",self.topology_view)
        if not self.is_topology_displayed:

            matplot = generate_network_topology(all_devices_data)
            canvas = FigureCanvasTkAgg(matplot.gcf(), master=self.topology_view)
            canvas.show()
            canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)
            self.is_topology_displayed = True

    def show(self, button_name, view_name):
        for button in self.buttons:
            if self.buttons[button].cget("highlightbackground") == 'cornflower blue' or self.buttons[button].cget("background") == 'cornflower blue':
                self.buttons[button].configure(highlightbackground="#bfbfbf", background="#bfbfbf")
        self.buttons[button_name].configure(background='cornflower blue', highlightbackground='cornflower blue')
        view_name.lift()

class Gui(tk.Frame):
    def __init__(self, master=None):
        tk.Frame.__init__(self, master=master)
        self.is_range_file = False
        self.pack(expand=False)
        self.report_data = {}
        self.is_pass_file = False
        self.param_types = (("Text File", "*.txt"), ("All Files", "*.*"))
        self.devices_type = (("Json File", "*.json"), ("All Files", "*.*"))
        row_offset = 0
        number_of_positions = 0
        self.net_ranges = self.text_entry_maker("Network IPs range: ", row_offset, number_of_positions)
        self.button_add_file_picker("Select network IP ranges file", self.param_types, row_offset,
                                   number_of_positions + 2, "range")
        self.net_user = self.text_entry_maker("Devices Username: ", row_offset + 1, number_of_positions)
        self.net_password = self.text_entry_maker("Devices Password: ", row_offset + 2, number_of_positions , show="*")
        self.button_add_file_picker("Select a file with passwords", self.param_types, row_offset + 2,
                                   number_of_positions + 2, "pass")
        self.cisco_client = self.text_entry_maker("Cisco Client ID: ", row_offset , number_of_positions + 3)
        self.cisco_secret = self.text_entry_maker("Cisco Secret: ", row_offset + 1, number_of_positions + 3, show="*")
        self.cisco_token = self.text_entry_maker("Cisco Token: ", row_offset + 2, number_of_positions + 3, show="*")
        entry_label = tk.Label(self)
        entry_label["text"] = "Load a previous report"
        entry_label.grid(row=row_offset+3, sticky=tk.E, padx=5, column=number_of_positions+2)
        self.button_add_file_picker("Select a previous report file (Json only)", self.devices_type, row_offset + 3,
                                   number_of_positions + 3, "report", button_text="Load a Report")
        self.execute_buton = tk.Button(self)
        self.execute_buton['text'] = 'Execute'
        self.execute_buton['command'] = self.get_network_informations
        self.execute_buton.grid(row=row_offset + 3, column=number_of_positions)
        self.save_buton = tk.Button(self)
        self.save_buton['text'] = 'Save reports'
        self.save_buton['command'] = lambda : self.save_reports(self.report_data)
        self.save_buton.grid(row=row_offset + 3, column=number_of_positions + 1)
        self.hide_widget(self.save_buton)

    @staticmethod
    def hide_widget(given_widget):
        given_widget.grid_remove()

    @staticmethod
    def show_widget(given_widget):
        given_widget.grid()

    def clear_window_elements(self):
        self.cisco_token.delete(0, tk.END)
        self.cisco_client.delete(0, tk.END)
        self.cisco_secret.delete(0, tk.END)
        self.net_password.delete(0, tk.END)
        self.net_ranges.delete(0, tk.END)
        self.net_user.delete(0, tk.END)
        self.is_range_file = False
        self.is_pass_file = False

    def save_reports(self, data):
        if data is None or not data:
            tkMessageBox.showerror("Error", "Please ensure the Execute Button was successfull")
            self.clear_window_elements()
            self.hide_widget(self.save_buton)
            return
        filename = tkFileDialog.asksaveasfilename(title="Enter or Select a file name",
                                                 filetypes=(("Json File", "*.json"), ("all files", "*.*")))
        try:
            resultCollectionMethod(data, filename, option="json")
        except Exception as exc:
            tkMessageBox.showerror("Error", "Something went wrong: ")
            print 'Error : %s' % (exc)
        self.clear_window_elements()
        self.hide_widget(self.save_buton)

    @staticmethod
    def open_files_gui(file_path_name):
        try:
            with open(file_path_name, "r") as ret_file:
                return ret_file.readlines()
                ret_file.close()
        except IOError:
            tkMessageBox.showerror("Excution Failure", "Could not execute your Request")
            return

    def get_network_informations(self):
        load_passwords = None
        load_ranges = None
        if not self.net_password.get()or not self.net_ranges.get():
            if tkMessageBox.askyesno("WARNING", "You must provide at list one IP range and one "
                                                "password or two files containing these values"
                                                "\nDo you want to proceed and use the Example "
                                                "files packed with this program?"
                                                "(You might end-up not having any results"
                                                " depending on your network)"):
                self.net_password.insert(0, "password.txt")
                self.net_ranges.insert(0, "range.txt")
                self.is_pass_file = True
                self.is_range_file = True
            else:
                return
        if self.net_ranges.get() and self.is_range_file:
            load_ranges = self.open_files_gui(self.net_ranges.get())
        elif self.net_ranges.get() and not self.is_range_file:
            load_ranges = [self.net_ranges.get()]
        if self.net_password.get() and self.is_pass_file:
            load_passwords = self.open_files_gui(self.net_password.get())
        elif self.net_password and not self.is_pass_file:
            load_passwords = self.net_password.get()
        if load_passwords is None or load_ranges is None:
            return
        self.execute_retrieval(load_ranges, load_passwords)

    def execute_retrieval(self, load_ranges, load_passwords):
        reachable_ips = check_iprange_and_retrieve_available_ips(load_ranges)
        if not self.net_user.get():
            self.net_user.insert(0, "admin")
        if isinstance(load_passwords, basestring):
            self.report_data = project_main_executor(
                reachable_ips, load_passwords, [load_passwords],
                self.net_user.get(), self.cisco_client.get(), self.cisco_secret.get(), self.cisco_token.get())
        else:
            self.report_data = project_main_executor(
                reachable_ips, None, load_passwords,
                self.net_user.get(), self.cisco_client.get(), self.cisco_secret.get(), self.cisco_token.get())
        if self.report_data is not None and bool(self.report_data):
            self.show_widget(self.save_buton)
            self.display_data(self.report_data)
        else:
            tkMessageBox.showerror("ERROR", "Execution Failed!\nMake sure you are connected "
                                            "to the network you want to investigate and that "
                                            "you provided correct parameters")
            self.clear_window_elements()
            self.is_range_file = False
            self.is_pass_file = False

    def display_data(self, data):
        root = tk.Tk()
        root.title("NETWORK DISCOVERY EXECUTION: RESULTS VIEW")
        devices_view = DevicesViewPane(data, master=root)
        devices_view.pack(side="top", fill="both", expand=True)
        root.geometry("1200x800")
        root.mainloop()

    def read_report(self, name):
        try:
            if self.save_buton.winfo_ismapped():
                if tkMessageBox.askokcancel("Warning", "You will not be able to Save the current "
                                                       "report later\n Do you want to proceed?"):
                    self.report_data = None
                    self.hide_widget(self.save_buton)
            report_file = open(name, "r")
            report_content = json.load(report_file)
            report_file.close()
            self.display_data(report_content)
        except (IOError) as ie:
            tkMessageBox.showerror("Error", "Could not open the file")
            print ie
            self.clear_window_elements()

    def button_add_file_picker(self, text, types, row_pos, colon_pos, conf, button_text=None):
        """ Handles the action of pressing the button 'Load Files'p
        """
        load_file = tk.Button(self)
        if button_text is None:
            load_file['text'] = "..."
        else:
            load_file['text'] = button_text
        load_file['command'] = lambda t=text, typ=types, cf=conf: self.load_configurations(t, typ, cf)
        load_file.grid(row=row_pos, column=colon_pos)

    def text_entry_maker(self, label, row_pos, colon_pos, show=""):
        entry_label = tk.Label(self)
        entry_label["text"] = label
        entry_label.grid(row=row_pos, sticky=tk.E, padx=5,
                        column=colon_pos)
        entry_widget_both = tk.Entry(self, show=show)
        entry_widget_both["width"] = 5
        entry_widget_both.grid(row=row_pos, column=colon_pos+1)
        return entry_widget_both

    def load_configurations(self, text, types, conf ):
        name = tkFileDialog.askopenfilename(filetypes=types,
                       title=text)
        if name:
            if conf == "range":
                self.net_ranges.delete(0, tk.END)
                self.net_ranges.insert(0, name)
                self.is_range_file = True
            elif conf == "pass":
                self.net_password.delete(0, tk.END)
                self.net_password.insert(0, name)
                self.is_pass_file = True
            else:
                self.read_report(name)


def gui():
    """Function that handles GUI interaction with this command Line tool

    This Function is called by executing the script without any argument
    """
    root = tk.Tk()
    root.title("NETWORK DISCOVERY EXECUTION")
    root["padx"] = 30
    root["pady"] = 20
    root.wm_geometry("650x200")
    gui_app = Gui(master=root)
    gui_app.grid(row=0, column=0, padx=10, pady=10)
    root.mainloop()
