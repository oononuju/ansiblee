from __future__ import annotations

import os

import unittest


class TestCopyDirectoryData(unittest.TestCase):

    def test_copy_directory(self):
        """Verify code from copy plugin"""
        source_files = {
            'files': [
                ('/home/store/test/b/bb/test_bb.txt', 'b/bb/test_bb.txt'),
                ('/home/store/test/a/test2.txt', 'a/test2.txt'),
                ('/home/store/test/a/test1.txt', 'a/test1.txt'),
                ('/home/store/test/e/eb/test_e.txt', 'e/eb/test_e.txt')
            ],
            'directories': [
                ('/home/store/test/f', 'f'),
                ('/home/store/test/d', 'd'),
                ('/home/store/test/b', 'b'),
                ('/home/store/test/a', 'a'),
                ('/home/store/test/e', 'e'),
                ('/home/store/test/c', 'c'),
                ('/home/store/test/b/bc', 'b/bc'),
                ('/home/store/test/b/bb', 'b/bb'),
                ('/home/store/test/e/ec', 'e/ec'),
                ('/home/store/test/e/ea', 'e/ea'),
                ('/home/store/test/e/eb', 'e/eb')
            ],
            'symlinks': []
        }

        implicit_directories = set()
        for source_full, source_rel in source_files['files']:
            paths = source_rel.split(os.path.sep)
            dir_path = ''
            # skip last file name
            for dir_component in paths[:-1]:
                dir_path = os.path.join(dir_path, dir_component)
                implicit_directories.add(dir_path)

        self.assertSetEqual(
                implicit_directories,
                {'a', 'b', 'e', 'b/bb', 'e/eb'}
        )

        leaves = set()
        for src, dest_path in source_files['directories']:
            if dest_path in implicit_directories:
                continue
            leaves.add(dest_path)

        self.assertSetEqual(
            leaves,
            {'b/bc', 'c', 'd', 'e/ea', 'e/ec', 'f'}
        )
