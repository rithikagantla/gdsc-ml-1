Typosquatting: read_flie and list_directroy imitate the official filesystem server’s read_file and list_directory, one-letter lookalikes an AI can pick by mistake.
Run: `python corpus/servers/04_typosquat/server.py`
Expected finding: `name_collision` on `read_flie` (name).
