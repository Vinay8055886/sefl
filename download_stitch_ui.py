import urllib.request
import os

urls = {
    "monitoring_dashboard.html": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ7Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpaCiVodG1sX2NiNzViYzE1YTAyMjQ2YzRiZTNhNjM1MDFhMjczNjJhEgsSBxDM5P6ZqRoYAZIBIwoKcHJvamVjdF9pZBIVQhM0NzM2MDc5NjYyNjQ1Mzk4MDY3&filename=&opi=89354086",
    "attack_simulator.html": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ7Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpaCiVodG1sXzE1Y2Q5YzZjYzhjMjQ2NjFiN2MxODEzN2Y5NmE3MjY3EgsSBxDM5P6ZqRoYAZIBIwoKcHJvamVjdF9pZBIVQhM0NzM2MDc5NjYyNjQ1Mzk4MDY3&filename=&opi=89354086",
    "self_healing_diagnostics.html": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ7Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpaCiVodG1sX2Y3YTViZDZmMjExOTQxOWZiYjNhNjZiZDI3NzBiZDg2EgsSBxDM5P6ZqRoYAZIBIwoKcHJvamVjdF9pZBIVQhM0NzM2MDc5NjYyNjQ1Mzk4MDY3&filename=&opi=89354086",
    "self_healing_technical_expansion.html": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ7Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpaCiVodG1sX2YyYWJiYzZjNWIxZTRlZDU5NDJhNzljNzI4NGQ2OGQ5EgsSBxDM5P6ZqRoYAZIBIwoKcHJvamVjdF9pZBIVQhM0NzM2MDc5NjYyNjQ1Mzk4MDY3&filename=&opi=89354086",
    "sentinel_lens_cyber_command.html": "https://contribution.usercontent.google.com/download?c=CgthaWRhX2NvZGVmeBJ7Eh1hcHBfY29tcGFuaW9uX2dlbmVyYXRlZF9maWxlcxpaCiVodG1sXzE5ZTc3ZDQyZTUwOTQyOTk4YTUzZWU2NGYwNGM0ZGNlEgsSBxDM5P6ZqRoYAZIBIwoKcHJvamVjdF9pZBIVQhM0NzM2MDc5NjYyNjQ1Mzk4MDY3&filename=&opi=89354086"
}

os.makedirs("stitch_ui", exist_ok=True)

for filename, url in urls.items():
    print(f"Downloading {filename}...")
    filepath = os.path.join("stitch_ui", filename)
    urllib.request.urlretrieve(url, filepath)
    print(f"Saved to {filepath}")

print("All downloads complete.")
