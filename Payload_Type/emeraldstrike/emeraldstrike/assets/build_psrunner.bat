@echo off
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe -nologo -target:exe -platform:anycpu -out:PSRunner.exe -r:"C:\Program Files (x86)\Reference Assemblies\Microsoft\WindowsPowerShell\3.0\System.Management.Automation.dll" PSRunner.cs
