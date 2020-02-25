from plugins.sandcat.app.utility.base_extension import Extension


def load():
    return P2pSmbPipe()


class P2pSmbPipe(Extension):

    def __init__(self):
        super().__init__(files=[
            ("guid.go", "winio/guid"),
            ("file.go", "winio"),
            ("hvsock.go", "winio"),
            ("pipe.go", "winio"),
            ("sd.go", "winio"),
            ("zsyscall_windows.go", "winio"),
            ("p2psmbpipe.go", "proxy"),
        ])
        self.dependencies = ['golang.org/x/sys/windows/mkwinsyscall']
