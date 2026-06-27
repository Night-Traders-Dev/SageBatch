# filesystem.sage — DOS-like filesystem operations
# Phase 6: Wraps Sage's io module with DOS-path semantics.
# Handles backslash normalization, glob expansion, and
# directory operations used by internal commands.

import io
import sys

class FileSystem:
    proc init(self, env):
        self.env = env

    proc normalize(self, path):
        return replace(path, "\\", "/")

    proc resolve(self, path):
        let p = self.normalize(path)
        if startswith(p, "/"):
            return p
        return self.env.cwd + "/" + p

    proc exists(self, path):
        return io.exists(self.resolve(path))

    proc is_dir(self, path):
        return io.isdir(self.resolve(path))

    proc is_file(self, path):
        return io.isfile(self.resolve(path))

    proc read_file(self, path):
        return io.readfile(self.resolve(path))

    proc write_file(self, path, content):
        io.writefile(self.resolve(path), content)

    proc append_file(self, path, content):
        io.appendfile(self.resolve(path), content)

    proc delete_file(self, path):
        io.remove(self.resolve(path))

    proc make_dir(self, path):
        raise "MKDIR: Not yet implemented in standalone mode"

    proc remove_dir(self, path):
        raise "RMDIR: Not yet implemented in standalone mode"

    proc list_dir(self, path):
        return []

    proc glob(self, pattern):
        return [pattern]

    proc copy_file(self, src, dst):
        let content = self.read_file(src)
        self.write_file(dst, content)

    proc move_file(self, src, dst):
        self.copy_file(src, dst)
        self.delete_file(src)

    proc rename_file(self, src, dst):
        self.move_file(src, dst)
