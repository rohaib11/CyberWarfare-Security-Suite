from PyQt5.QtWidgets import *
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

class LiveGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        
        # Create the plot area
        self.figure = Figure(facecolor='#1e1e1e') # Dark background
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(self.canvas)
        
        # Setup the CPU Axis
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor('#2d2d2d')
        self.ax.set_title('Live System Load', color='white')
        self.ax.set_ylim(0, 100) # 0 to 100%
        self.ax.grid(True, color='#444', linestyle='--')
        
        # Style the axis text
        self.ax.tick_params(axis='x', colors='white')
        self.ax.tick_params(axis='y', colors='white')
        
        # Data storage
        self.x_data = list(range(60)) # 60 seconds
        self.y_cpu = [0] * 60
        self.y_ram = [0] * 60
        
        # Create lines
        self.line_cpu, = self.ax.plot(self.x_data, self.y_cpu, 'r-', label='CPU %') # Red Line
        self.line_ram, = self.ax.plot(self.x_data, self.y_ram, 'c-', label='RAM %') # Cyan Line
        
        self.ax.legend(loc='upper left', facecolor='#333', labelcolor='white')

    def update_graph(self, cpu_val, ram_val):
        # Shift data to the left
        self.y_cpu.pop(0)
        self.y_cpu.append(cpu_val)
        
        self.y_ram.pop(0)
        self.y_ram.append(ram_val)
        
        # Update lines
        self.line_cpu.set_ydata(self.y_cpu)
        self.line_ram.set_ydata(self.y_ram)
        
        self.canvas.draw()