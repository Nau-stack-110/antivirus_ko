import calendar
import tkinter as tk
from tkinter import *

def custom_exit_handler():
    print('You clicked exit button')
    root.destroy()   
    
def printCalendar():
    year = int(year_entry.get())
    cal = calendar.TextCalendar().formatyear(year, 2,1,1,3)
    result_text.delete(1.0, END)
    result_text.insert(INSERT, cal)

root = tk.Tk()
root.title("calendar_nay")
root.geometry('700x600')

# frame
calendar_frame = tk.Frame(root)
calendar_frame.pack(pady=10)

# label
year_label = tk.Label(calendar_frame, text="year : ")
year_label.grid(row=0, column=0, padx=5)

# get the input
year_entry = tk.Entry(calendar_frame)
year_entry.grid(row=0, column=1, padx=5)

# button to show calendar
bouton = tk.Button(calendar_frame, text = "Show calendar Year",command=printCalendar)
bouton.grid(row=0, column=2 , padx=5)

# result the print calendar
result_text_frame = tk.Frame(root)
result_text_frame.pack(pady=4)

# result text in the frame
result_text = tk.Text(result_text_frame, height=20, width=55, wrap="none")
result_text.grid(row=0, column=0)

# scrollbar to go to the end of frame vertical
scrollbar = tk.Scrollbar(result_text_frame, command=result_text.yview)
scrollbar.grid(row=0, column=1, sticky='nsew')
result_text['yscrollcommand'] = scrollbar.set

# scrollbar to go to the end of frame horizontal
scrollbar = tk.Scrollbar(result_text_frame,command=result_text.xview, orient="horizontal")
scrollbar.grid(row=1, column=0, sticky='nsew')
result_text['xscrollcommand'] = scrollbar.set

root.protocol("WM_DELETE_WINDOW", custom_exit_handler)
root.mainloop()



