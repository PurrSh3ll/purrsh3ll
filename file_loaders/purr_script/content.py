import logging
import os, re, ast, sys, json, random, shutil, subprocess, threading, time, tempfile
from collections import deque

logger = logging.getLogger(__name__)
import pydoc
import importlib.util

from PyQt6.QtGui import QDesktopServices
from PyQt6.QtCore import QUrl

from pyfiglet import Figlet

class ContentMixin:
    def update_mtime(self, mtime):
        if self.file_mtime is None:
            self.file_mtime = mtime
        else:
            if self.file_mtime != mtime:
                self.file_mtime = mtime

                self.btn_refresh_interpreter.click()
                self.update_docs()
                self.update_help()

    def _make_ascii_title(self) -> str:
        fonts_list = ['ansi_regular', 'big_money-nw', 'dos_rebel', 'starwars', 'sub-zero', 'big_money-sw', 'smmono12',
                      'big_money-se', 'ansi_shadow', 'larry3d', 'mono9', 'roman', 'big_money-ne', 'blocky', 'poison']

        asci_font = random.choice(fonts_list)
        art = Figlet(font=asci_font)
        name = art.renderText(self.name)
        return name

    def update_imports_info(self):
        self.info_field.setPlainText(self.check_imports())

    def check_imports(self):
        def resolve_module_to_path(module_name, project_root):
            if not module_name:
                return None

            parts = module_name.split('.')
            candidate = os.path.join(project_root, *parts) + ".py"
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)

            candidate_init = os.path.join(project_root, *parts, "__init__.py")
            if os.path.isfile(candidate_init):
                return os.path.abspath(candidate_init)

            first = parts[0]
            candidate_first = os.path.join(project_root, first + ".py")
            if os.path.isfile(candidate_first):
                return os.path.abspath(candidate_first)
            candidate_first_pkg = os.path.join(project_root, first, "__init__.py")
            if os.path.isfile(candidate_first_pkg):
                return os.path.abspath(candidate_first_pkg)

            return None

        def find_imports_in_file(path):
            imports = []
            try:
                with open(path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=path)
            except (SyntaxError, UnicodeDecodeError, FileNotFoundError):
                return imports

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(("import", alias.name, 0))
                elif isinstance(node, ast.ImportFrom):
                    imports.append(("from", node.module, node.level or 0))
            return imports

        def collect_project_libraries():
            project_root = os.path.dirname(os.path.abspath(self.path))
            q = deque()
            q.append(os.path.abspath(self.path))
            visited_files = set()
            libraries = set()
            visited_modules = set()

            while q:
                filepath = q.popleft()
                if filepath in visited_files:
                    continue
                visited_files.add(filepath)

                for typ, module, level in find_imports_in_file(filepath):
                    if typ == "import":
                        top_name = module.split('.')[0]
                        resolved = resolve_module_to_path(module, project_root)
                        if resolved:
                            if resolved not in visited_files:
                                q.append(resolved)
                        else:
                            libraries.add(top_name)
                    elif typ == "from":
                        if level and level > 0:
                            cur_dir = os.path.dirname(filepath)
                            target_dir = cur_dir
                            for _ in range(level - 1):
                                target_dir = os.path.dirname(target_dir)
                            if module:
                                rel_path = os.path.join(target_dir, *module.split('.')) + ".py"
                                rel_init = os.path.join(target_dir, *module.split('.'), "__init__.py")
                                if os.path.isfile(rel_path):
                                    resolved = os.path.abspath(rel_path)
                                elif os.path.isfile(rel_init):
                                    resolved = os.path.abspath(rel_init)
                                else:
                                    libraries.add(module.split('.')[0] if module else '')
                                    resolved = None
                            else:
                                cand_init = os.path.join(target_dir, "__init__.py")
                                cand_file = target_dir + ".py"
                                if os.path.isfile(cand_init):
                                    resolved = os.path.abspath(cand_init)
                                elif os.path.isfile(cand_file):
                                    resolved = os.path.abspath(cand_file)
                                else:
                                    resolved = None
                            if resolved and resolved not in visited_files:
                                q.append(resolved)
                        else:
                            if module:
                                resolved = resolve_module_to_path(module, project_root)
                                if resolved:
                                    if resolved not in visited_files:
                                        q.append(resolved)
                                else:
                                    libraries.add(module.split('.')[0])
                            else:
                                pass

            return sorted(libraries), sorted(visited_files)

        def chck_missing_imp():
            interpreter = self.cmb_interpreter.currentText().strip()
            if not interpreter:
                return _python_not_found()

            json_path = self.controller.interpreters_json
            if not os.path.exists(json_path):
                return _python_not_found()

            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                return _python_not_found()

            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                return _python_not_found()

            entry = next((e for e in data if e.get("path") == interpreter), None)
            if not entry:
                return _python_not_found()

            package_names = {
                                str(item["name"])
                                for item in entry.get("packages", [])
                                if isinstance(item, dict) and item.get("name")
                            } | {
                                item
                                for item in entry.get("packages", [])
                                if isinstance(item, str)
                            }

            libs, _ = collect_project_libraries()
            script_libs = set(libs)
            python_libs = package_names | self.controller.build_in_libs

            missing_libs = script_libs - python_libs

            try:
                with open(self.controller.imports_map_json, "r", encoding="utf-8") as f:
                    imports_map = json.load(f)
            except (OSError, json.JSONDecodeError):
                imports_map = {}

            normalized_map = {
                k: v if isinstance(v, list) else [v]
                for k, v in imports_map.items()
                if isinstance(v, (list, str))
            }

            final_missing = set()
            unmapped = set()

            for imp in missing_libs:
                if imp in normalized_map:
                    suggested = normalized_map[imp]
                    if not any(pkg in python_libs for pkg in suggested):
                        final_missing.update(suggested)
                else:
                    unmapped.add(imp)

            if not final_missing and not unmapped:
                self.missing_libs = None
                self.install_btn.setEnabled(False)
                return "Python libraries ok"

            missing = sorted(final_missing | unmapped)
            self.missing_libs = " ".join(missing)
            self.install_btn.setEnabled(True)
            return f"Missing Python libraries: {', '.join(missing)}"

        def _python_not_found():
            self.missing_libs = None
            self.install_btn.setEnabled(False)
            return "Python not found"

        return chck_missing_imp()

    def update_readme(self):
        allowed_ext = {"", "txt", "rst", "readme", "md", "html"}
        folder = os.path.dirname(self.path)
        found = []

        try:
            for filename in os.listdir(folder):
                name, ext = os.path.splitext(filename)
                name = name.lower()
                ext = ext.lstrip(".").lower()

                if name == "readme" and ext in allowed_ext:
                    found.append(os.path.join(folder, filename))

        except FileNotFoundError:
            self.readme_text = "The specified path does not exist."
            self.readme_format = "plain"
            return

        if not found:
            self.readme_text = "[-] No readme file found."
            self.readme_format = "plain"
            return

        if len(found) > 1:
            self.readme_text = (
                    "Multiple readme files were found.\n"
                    "Cannot determine which file is correct:\n"
                    + "\n".join(f" - {f}" for f in found)
            )
            self.readme_format = "plain"
            return

        readme_path = found[0]
        _, ext = os.path.splitext(readme_path)
        ext = ext.lstrip(".").lower()

        try:
            with open(readme_path, "r", encoding="utf-8", errors="replace") as f:
                self.readme_text = f.read()

            if ext == "md":
                self.readme_format = "markdown"
            elif ext == "html":
                self.readme_format = "html"
            else:
                self.readme_format = "plain"

        except Exception as e:
            self.readme_text = f"Failed to read the readme file: {e}"
            self.readme_format = "plain"

    def update_help(self, timeout_seconds: int = 5):

        NO_HELP = "[-] No Help documentation found."

        if not hasattr(self, "path") or not self.path or not os.path.isfile(self.path):
            self.help_text = NO_HELP
            return

        if self.script_help_path is not None:
            if os.path.getsize(self.script_help_path) != 0:
                try:
                    with open(self.script_help_path, "r", encoding="utf-8") as f:
                        source = f.read()
                        self.help_text = "[+] Help documentation found (local cache)\n\n" + source
                        return
                except Exception as e:
                    pass

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                source = f.read()
        except Exception:
            self.help_text = NO_HELP
            return

        const_map = {}
        for m in re.finditer(r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*[\'"]([^\'"]+)[\'"]\s*$', source):
            name = m.group(1)
            val = m.group(2)
            const_map[name] = val

        sys_usage = False
        if re.search(r'\bsys\.argv\b', source):
            sys_usage = True
        if re.search(r'(?m)^\s*from\s+sys\s+import\s+argv\b', source):
            sys_usage = True

        if sys_usage:
            vars_found = set()

            for m in re.finditer(r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*sys\.argv\b', source):
                vars_found.add(m.group(1))

            for m in re.finditer(r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*sys\.argv\s*\[.*?\]', source):
                vars_found.add(m.group(1))

            for m in re.finditer(r'(?m)^\s*for\s+([A-Za-z_]\w*)\s+in\s+sys\.argv\b', source):
                vars_found.add(m.group(1))

            for m in re.finditer(r'(?m)^\s*from\s+sys\s+import\s+argv(?:\s+as\s+([A-Za-z_]\w*))?', source):
                alias = m.group(1) or "argv"
                vars_found.add(alias)

            for m in re.finditer(r'(?m)^\s*([\sA-Za-z0-9_,]+?)\s*=\s*sys\.argv\b', source):
                left = m.group(1)
                names = [p.strip() for p in left.split(",") if p.strip()]
                for n in names:
                    if re.match(r'^[A-Za-z_]\w*$', n):
                        vars_found.add(n)

            direct_imports = []
            for m in re.finditer(r'(?m)^\s*from\s+sys\s+import\s+argv(?:\s+as\s+([A-Za-z_]\w*))?', source):
                direct_imports.append(m.group(1) or "argv")
            if direct_imports:
                for name in direct_imports:
                    for m in re.finditer(r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*' + re.escape(name) + r'\b', source):
                        vars_found.add(m.group(1))
                    for m in re.finditer(r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*' + re.escape(name) + r'\s*\[.*?\]', source):
                        vars_found.add(m.group(1))
                    for m in re.finditer(r'(?m)^\s*for\s+([A-Za-z_]\w*)\s+in\s+' + re.escape(name) + r'\b', source):
                        vars_found.add(m.group(1))

            env_keys = set()
            env_idents = set()
            resolved_keys = set()
            env_var_assigns = {}

            for m in re.finditer(
                    r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*\.)?environ\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]', source):
                left_var = m.group(1)
                key = m.group(2)
                env_keys.add(key)
                env_var_assigns[left_var] = key

            for m in re.finditer(
                    r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*\.)?environ\.get\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))',
                    source):
                left_var = m.group(1)
                token = m.group(2)
                if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
                    key = token[1:-1]
                    env_keys.add(key)
                    env_var_assigns[left_var] = key
                else:
                    env_idents.add(token)
                    env_var_assigns[left_var] = token

            for m in re.finditer(
                    r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*\.)?getenv\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))',
                    source):
                left_var = m.group(1)
                token = m.group(2)
                if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
                    key = token[1:-1]
                    env_keys.add(key)
                    env_var_assigns[left_var] = key
                else:
                    env_idents.add(token)
                    env_var_assigns[left_var] = token

            for m in re.finditer(
                    r'(?m)(?:[A-Za-z_]\w*\.)?environ\.get\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))', source):
                g = m.group(1)
                if (g.startswith('"') and g.endswith('"')) or (g.startswith("'") and g.endswith("'")):
                    env_keys.add(g[1:-1])
                else:
                    env_idents.add(g)

            for m in re.finditer(r'(?m)(?:[A-Za-z_]\w*\.)?getenv\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))',
                                 source):
                g = m.group(1)
                if (g.startswith('"') and g.endswith('"')) or (g.startswith("'") and g.endswith("'")):
                    env_keys.add(g[1:-1])
                else:
                    env_idents.add(g)

            if re.search(r'(?m)from\s+os\s+import\s+getenv\b', source):
                for m in re.finditer(r'(?m)getenv\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))', source):
                    g = m.group(1)
                    if (g.startswith('"') and g.endswith('"')) or (g.startswith("'") and g.endswith("'")):
                        env_keys.add(g[1:-1])
                    else:
                        env_idents.add(g)

            for m in re.finditer(r'(?m)^\s*import\s+os\s+as\s+([A-Za-z_]\w*)', source):
                alias = m.group(1)
                for mm in re.finditer(r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*' + re.escape(
                        alias) + r'\.getenv\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))', source):
                    left_var = mm.group(1)
                    token = mm.group(2)
                    if (token.startswith('"') and token.endswith('"')) or (
                            token.startswith("'") and token.endswith("'")):
                        key = token[1:-1]
                        env_keys.add(key)
                        env_var_assigns[left_var] = key
                    else:
                        env_idents.add(token)
                        env_var_assigns[left_var] = token
                for mm in re.finditer(r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*' + re.escape(
                        alias) + r'\.environ\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]', source):
                    left_var = mm.group(1)
                    key = mm.group(2)
                    env_keys.add(key)
                    env_var_assigns[left_var] = key
                for mm in re.finditer(
                        r'(?m)' + re.escape(alias) + r'\.getenv\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))',
                        source):
                    g = mm.group(1)
                    if (g.startswith('"') and g.endswith('"')) or (g.startswith("'") and g.endswith("'")):
                        env_keys.add(g[1:-1])
                    else:
                        env_idents.add(g)

            for ident in env_idents:
                if ident in const_map:
                    resolved_keys.add(const_map[ident])
                else:
                    resolved_keys.add(f"<{ident}>")

            all_env_keys = sorted(env_keys | resolved_keys)

            assigned_pairs = []
            for var, keytok in sorted(env_var_assigns.items()):
                if keytok in const_map:
                    assigned_pairs.append(f"{var} -> {const_map[keytok]}")
                elif (isinstance(keytok, str) and ((keytok.startswith('"') and keytok.endswith('"')) or (
                        keytok.startswith("'") and keytok.endswith("'")))):
                    assigned_pairs.append(f"{var} -> {keytok[1:-1]}")
                else:
                    if keytok in resolved_keys:
                        assigned_pairs.append(f"{var} -> {keytok}")
                    else:
                        assigned_pairs.append(f"{var} -> <{keytok}>")

            if vars_found:
                line = "Variables/aliases associated with sys.argv (best-effort): " + ", ".join(sorted(vars_found))
                if all_env_keys:
                    line += "\n\nEnvironment variable keys accessed (best-effort): " + ", ".join(all_env_keys)
                if assigned_pairs:
                    line += "\n\nAssignments from env keys (best-effort): " + "; ".join(assigned_pairs)
                line = "[+] Help documentation found (sys arg var)\n\n" + line
                self.help_text = line
            else:
                if all_env_keys or assigned_pairs:
                    line = "[+] Help documentation found (sys arg var)\n\n"
                    line += "sys.argv usage detected, but no assigned variable names found.\n\n"
                    if all_env_keys:
                        line += "Environment variable keys accessed (best-effort): " + ", ".join(all_env_keys) + "\n\n"
                    if assigned_pairs:
                        line += "Assignments from env keys (best-effort): " + "; ".join(assigned_pairs)
                    self.help_text = line
                else:
                    self.help_text = "sys.argv usage detected, but no assigned variable names found."
            return

        try:
            tree = ast.parse(source, filename=self.path)
        except Exception:
            self.help_text = NO_HELP
            return

        modules = {"argparse": False, "optparse": False, "click": False, "typer": False}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in modules:
                        modules[alias.name] = True
            elif isinstance(node, ast.ImportFrom):
                if node.module in modules:
                    modules[node.module] = True

        used = [name for name, found in modules.items() if found]

        if not used:
            env_detected = []

            for m in re.finditer(
                    r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*\.)?environ\.get\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))',
                    source):
                left = m.group(1)
                tok = m.group(2)
                if (tok.startswith('"') and tok.endswith('"')) or (tok.startswith("'") and tok.endswith("'")):
                    key = tok[1:-1]
                else:
                    key = const_map.get(tok, f"<{tok}>")
                env_detected.append((left, key))

            for m in re.finditer(
                    r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*\.)?getenv\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))',
                    source):
                left = m.group(1)
                tok = m.group(2)
                if (tok.startswith('"') and tok.endswith('"')) or (tok.startswith("'") and tok.endswith("'")):
                    key = tok[1:-1]
                else:
                    key = const_map.get(tok, f"<{tok}>")
                env_detected.append((left, key))

            for m in re.finditer(
                    r'(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:[A-Za-z_]\w*\.)?environ\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]', source):
                left = m.group(1)
                key = m.group(2)
                env_detected.append((left, key))

            nonassigned_keys = set()
            for m in re.finditer(
                    r'(?m)(?:[A-Za-z_]\w*\.)?environ\.get\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))', source):
                tok = m.group(1)
                if (tok.startswith('"') and tok.endswith('"')) or (tok.startswith("'") and tok.endswith("'")):
                    nonassigned_keys.add(tok[1:-1])
                else:
                    nonassigned_keys.add(const_map.get(tok, f"<{tok}>"))
            for m in re.finditer(r'(?m)(?:[A-Za-z_]\w*\.)?getenv\s*\(\s*([A-Za-z_]\w*|[\'"][^\'"]+[\'"])\s*(?:,|\))',
                                 source):
                tok = m.group(1)
                if (tok.startswith('"') and tok.endswith('"')) or (tok.startswith("'") and tok.endswith("'")):
                    nonassigned_keys.add(tok[1:-1])
                else:
                    nonassigned_keys.add(const_map.get(tok, f"<{tok}>"))

            if env_detected or nonassigned_keys:
                lines = ["[+] Help documentation found (env var)", ""]
                for left, key in env_detected:
                    lines.append(f"{left} -> {key}")
                if nonassigned_keys:
                    lines.append("")
                    lines.append("Environment keys used (best-effort): " + ", ".join(sorted(nonassigned_keys)))
                self.help_text = "\n".join(lines)
                return

            self.help_text = NO_HELP
            return

        if not used:
            self.help_text = NO_HELP
            return

        if len(used) == 1:
            mod_info = f"{used[0]} module used"
        else:
            mod_info = f"{', '.join(used)} modules used"
        header = f"[+] Help documentation found ({mod_info}):"

        def _preexec_limits():
            os.setsid()
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
            except Exception:
                pass
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
            except Exception:
                pass
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            except Exception:
                pass

        python_exec = shutil.which("python") or shutil.which("python3") or "python"

        unshare_path = shutil.which("unshare")
        use_unshare = False
        unshare_cmd = []
        if unshare_path:
            unshare_cmd = [
                unshare_path,
                "--net",
                "--pid",
                "--mount",
                "--fork",
                "--map-root-user",
                "--mount-proc"
            ]
            use_unshare = True

        help_output = ""
        help_error = ""

        for flag in ("--help", "-h"):

            with tempfile.TemporaryDirectory(prefix="help_sandbox_") as tmpcwd:
                env = {
                    "PYTHONIOENCODING": "utf-8",
                    "PATH": "/usr/bin:/bin",
                }

                if use_unshare:
                    cmd = unshare_cmd + [python_exec, "-E", self.path, flag]
                else:
                    cmd = [python_exec, "-E", self.path, flag]

                proc = None
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=tmpcwd,
                        env=env,
                        preexec_fn=_preexec_limits,
                        text=True
                    )

                    try:
                        stdout, stderr = proc.communicate(timeout=timeout_seconds)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except Exception:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                        try:
                            stdout, stderr = proc.communicate(timeout=1)
                        except Exception:
                            stdout, stderr = ("", "Process timed out and was killed.")
                        help_error = "Process timed out and was killed."
                        break

                    stdout = (stdout or "").strip()
                    stderr = (stderr or "").strip()

                    if stdout:
                        help_output = stdout
                        break
                    if stderr:
                        help_error = stderr
                        break

                except Exception as e:
                    help_error = str(e)
                    if proc and proc.poll() is None:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except Exception:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                    break
                finally:
                    if proc and proc.poll() is None:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except Exception:
                            try:
                                proc.kill()
                            except Exception:
                                pass

        if help_output:
            self.help_text = header + "\n\n" + help_output
            return

        if help_error:
            lines = help_error.splitlines()
            cleaned = []
            for line in lines:
                if line.strip().startswith("Traceback (most recent call last):"):
                    continue
                if re.match(r'\s*File ".*", line \d+(, in .*)?', line):
                    continue
                if "Traceback" in line and line.strip().startswith("Traceback"):
                    continue
                cleaned.append(line)
            cleaned_error = "\n".join(cleaned).strip()
            if not cleaned_error:
                cleaned_error = "An error occurred but specific message could not be retrieved."
        else:
            cleaned_error = "No help output could be retrieved."

        self.help_text = header + "\n\nAn error occurred while trying to retrieve help:\n" + cleaned_error

    def update_notes(self):

        path = self.script_note_path

        if not os.path.exists(path):
            self.notes_text = ""
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
        except Exception:
            self.notes_text = ""
            return

        if not content:
            self.notes_text = ""
            return

        self.notes_text = content

    def update_history(self):
        path = self.script_history_path

        if not os.path.exists(path):
            self.history_text = "[-] Execution history is empty. The program has not been launched."
            return

        try:
            with open(path, "r", encoding="utf-8", newline="") as f:
                content = f.read()
        except Exception as e:
            self.history_text = "[-] Execution history is empty. The program has not been launched."
            return

        if not content:
            self.history_text = "[-] Execution history is empty. The program has not been launched."
            return

        self.history_text = content

    def update_docs(self):

        NO_DOC = "[-] No Docstrings documentation found."

        try:
            if not hasattr(self, "path") or not self.path:
                return

            if not os.path.isfile(self.path):
                return

            if self.script_docs_path is not None:
                if os.path.getsize(self.script_docs_path) != 0:
                    try:
                        with open(self.script_docs_path, "r", encoding="utf-8") as f:
                            source = f.read()
                            self.docs_text = "[+] Found Documentation Strings (loacl cache) \n\n" + source
                            return
                    except Exception as e:
                        pass

            source = open(self.path, "r", encoding="utf-8").read()
            tree = ast.parse(source, filename=self.path)

            found_docs = []

            module_doc = ast.get_docstring(tree)
            if module_doc and module_doc.strip():
                found_docs.append(f"Module:\n{module_doc.strip()}")

            def visit(node_list, class_prefix=None):
                for node in node_list:

                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        name = node.name
                        doc = ast.get_docstring(node)

                        if doc and doc.strip():
                            if class_prefix:
                                label = (
                                    f"Method {class_prefix}.{name}:"
                                    if isinstance(node, ast.FunctionDef)
                                    else f"Async Method {class_prefix}.{name}:"
                                )
                            else:
                                label = (
                                    f"Function {name}:"
                                    if isinstance(node, ast.FunctionDef)
                                    else f"Async Function {name}:"
                                )

                            found_docs.append(f"{label}\n{doc.strip()}")

                        visit(node.body, class_prefix)

                    elif isinstance(node, ast.ClassDef):
                        cname = node.name
                        doc = ast.get_docstring(node)

                        if doc and doc.strip():
                            found_docs.append(f"Class {cname}:\n{doc.strip()}")

                        for item in node.body:
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                                visit([item], class_prefix=cname)

            visit(tree.body)

            if not found_docs:
                self.docs_text = NO_DOC
            else:
                self.docs_text = "[+] Found Documentation Strings \n\n" + "\n\n".join(found_docs)

        except Exception as e:
            logger.warning("Failed to parse docstrings for %s", self.path, exc_info=True)
