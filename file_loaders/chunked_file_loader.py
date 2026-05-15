import os
import stat
import tempfile

class ChunkedFileLoader:

    def _write_chunks_to_disk(self, chunks_list, path):
        try:
            data = "".join(chunks_list)
            dirpath = os.path.dirname(path) or "."

            old_mode = None
            old_atime = None
            old_mtime = None
            try:
                st = os.stat(path)
                old_mode = stat.S_IMODE(st.st_mode)
                old_atime = st.st_atime
                old_mtime = st.st_mtime
            except FileNotFoundError:
                old_mode = None
            except Exception as e:
                old_mode = None

            tmpf = None
            try:
                tmpf = tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=dirpath,
                                                   prefix=".tmp_write_", suffix=".tmp")
                try:
                    tmpf.write(data.encode("utf-8"))
                    tmpf.flush()
                    os.fsync(tmpf.fileno())
                except Exception:
                    try:
                        tmpf.close()
                    except Exception:
                        pass
                    try:
                        if os.path.exists(tmpf.name):
                            os.remove(tmpf.name)
                    except Exception:
                        pass
                    raise

                if old_mode is not None:
                    try:
                        try:
                            os.fchmod(tmpf.fileno(), old_mode)
                        except AttributeError:
                            pass
                    except Exception as e:
                        pass

                try:
                    tmpf.close()
                except Exception:
                    pass

                if old_mode is not None:
                    try:
                        os.chmod(tmpf.name, old_mode)
                    except Exception as e:
                        pass

                os.replace(tmpf.name, path)

                if old_atime is not None and old_mtime is not None:
                    try:
                        os.utime(path, (old_atime, old_mtime))
                    except Exception as e:
                        pass

                if old_mode is not None:
                    try:
                        os.chmod(path, old_mode)
                    except Exception as e:
                        pass

            except Exception as e:
                try:
                    if tmpf is not None:
                        tmp_name = tmpf.name
                        try:
                            tmpf.close()
                        except Exception:
                            pass
                        if os.path.exists(tmp_name):
                            try:
                                os.remove(tmp_name)
                            except Exception:
                                pass
                except Exception:
                    pass
                raise

        except Exception as e:
            return

    def _cleanup_thread(self, threads_list, thread_ref):
        try:
            if threads_list is None:
                return
            try:
                while thread_ref in threads_list:
                    threads_list.remove(thread_ref)
            except ValueError:
                pass
        except Exception:
            pass
