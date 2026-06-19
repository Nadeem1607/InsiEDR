import PyInstaller.__main__
import os

# Run PyInstaller for RunAgent
PyInstaller.__main__.run([
    'RunAgent_src.py',
    '--onefile',
    '--windowed',
    '--name=RunAgent',
    '--clean'
])

# Run PyInstaller for StopAgent
PyInstaller.__main__.run([
    'StopAgent_src.py',
    '--onefile',
    '--windowed',
    '--name=StopAgent',
    '--clean'
])
