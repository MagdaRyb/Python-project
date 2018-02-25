try:
    import Tkinter as tk
    import Tkinter, Tkconstants, tkFileDialog
    import tkMessageBox
    import sys
    import json
    from ciscoIncubatorProjectGroup11 import generate_network_topology, \
        resultCollectionMethod, project_main_executor, check_iprange_and_retrieve_available_ips
except ImportError as tk_err:
    print 'Failed to start the GUI, please make sure you install [tkinter]', tk_err
    sys.exit(1)


class DeviceViewPane(tk.Frame):

    def __init__(self, device_data, name, master=None):
        tk.Frame.__init__(self, master)
        self.save_buton = tk.Button(self)
        self.save_buton['text'] = 'Save reports ' + name
        self.save_buton['command'] = lambda: self.save_reports(self.report_data)
        self.save_buton.grid(row=1, column=1)

    @staticmethod
    def show(view, btn ):
            view.lift()
            btn.configure()


class DevicesViewPane(tk.Frame):
    def __init__(self, devices_data, master=None):
        tk.Frame.__init__(self, master)
        button_frame = tk.Frame(self)
        main_container = tk.Frame(self)
        button_frame.pack(side="top", fill="x", expand=False)
        main_container.pack(side="top", fill="both", expand=True)
        device_to = None
        for device in devices_data:
            device_view = DeviceViewPane(devices_data[device], device, master=master)
            device_view.place(in_=main_container, x=0, y=0, relwidth=1, relheight=1)
            self.button = tk.Button(button_frame, text=device, command=device_view.lift)
            self.button.pack(side="left")
            if device_to is None:
                device_to = device_view
        if device_to is not None:
            device_to.lift()


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
            tkMessageBox.showerror("Error", "Please ensure the Execute Button  click was successfull")
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
            return open(file_path_name, 'r')
        except IOError as ioe:
            tkMessageBox.showerror("Excution Failure", "Could not execute your Request", ioe)
            return

    def get_network_informations(self):
        load_passwords = None
        load_ranges = None
        if not(self.net_password.get(), self.net_ranges.get()):
            if tkMessageBox.askyesokcancel("WARNING", "You must provide at list one IP range and one "
                                                      "password or two files containing these values"
                                                      "Do you want to proceed and use the Example "
                                                      "files packed with this program?"
                                                      "(You might end-up not having any results"
                                                      " depending on your network)"):
                self.net_password.insert(0, "password.txt")
                self.net_ranges.insert(0, "range.txt")
                load_passwords = self.open_files_gui(self.net_password.get())
                load_ranges = self.open_files_gui(self.net_ranges.get())

            else:
                return
        if self.net_ranges.get() and self.is_range_file:
            load_ranges = self.open_files_gui(self.net_ranges.get())
        elif self.net_ranges.get():
            load_ranges = [self.net_ranges.get()]
        if self.net_password.get() and self.is_pass_file:
            load_passwords = self.open_files_gui(self.net_password.get())
        elif self.net_password:
            load_passwords = self.net_password.get()

        if load_passwords is None or load_ranges is None:
            return
        reachable_ips = check_iprange_and_retrieve_available_ips(load_ranges)
        self.report_data = project_main_executor(
            reachable_ips, self.net_password.get(), load_passwords,
            self.net_user.get(), self.cisco_client.get(), self.cisco_secret.get(), self.cisco_token.get())
        if self.report_data is not None:
            self.show_widget(self.save_buton)
            self.display_data(self.report_data)

    def display_data(self, data):
        root = tk.Tk()
        root.title("NETWORK DISCOVERY EXECUTION: RESULTS VIEW")
        devices_view = DevicesViewPane(data, master=root)
        devices_view.pack(side="top", fill="both", expand=True)
        root.wm_geometry("800x800")
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
