# Configuration file for jupyter-server.
# Adapted from https://github.com/jupyter/docker-stacks/blob/main/images/base-notebook/jupyter_server_config.py

c = get_config()  #noqa

# Listen on all interfaces (ipv4 and ipv6)
c.ServerApp.ip = ""
c.ServerApp.open_browser = False

# to output both image/svg+xml and application/pdf plot formats in the notebook file
c.InlineBackend.figure_formats = {"png", "jpeg", "svg", "pdf"}

# https://github.com/jupyter/notebook/issues/3130
c.FileContentsManager.delete_to_trash = False
