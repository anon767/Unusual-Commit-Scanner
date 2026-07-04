import re

path = "/home/deploy/youtube-plays-nds/services/input_controller/input_controller.py"
with open(path) as f:
    content = f.read()

old = """        try:
            target_window = await self._get_target_window()
            if not target_window:
                logger.error("No DeSmuME windows found")
                return False

            await self._run_xdotool('windowactivate', '--sync', target_window, timeout=0.3)

            await self._run_xdotool(
                'keydown', '--clearmodifiers', '--window', target_window, key, timeout=0.3
            )

            await asyncio.sleep(duration_seconds)

            await self._run_xdotool(
                'keyup', '--clearmodifiers', '--window', target_window, key, timeout=0.3
            )
            logger.debug(f"Successfully executed command: {command} (key: {key}) on window {target_window}")
            return True
            
        except Exception as e:"""

new = """        target_window = None
        key_pressed = False
        try:
            target_window = await self._get_target_window()
            if not target_window:
                logger.error("No DeSmuME windows found")
                return False

            await self._run_xdotool('windowactivate', '--sync', target_window, timeout=0.3)

            await self._run_xdotool(
                'keydown', '--clearmodifiers', '--window', target_window, key, timeout=0.3
            )
            key_pressed = True

            await asyncio.sleep(duration_seconds)

            await self._run_xdotool(
                'keyup', '--clearmodifiers', '--window', target_window, key, timeout=0.3
            )
            key_pressed = False
            logger.debug(f"Successfully executed command: {command} (key: {key}) on window {target_window}")
            return True
            
        except Exception as e:"""

assert old in content, "old block not found"
content = content.replace(old, new)

old2 = """        except Exception as e:
            logger.error(f"Error executing command: {e}")
            self._invalidate_window_cache()
            return False"""

new2 = """        except Exception as e:
            logger.error(f"Error executing command: {e}")
            self._invalidate_window_cache()
            return False
        finally:
            # Guard against a stuck key if keyup failed/was skipped above
            if key_pressed and target_window:
                try:
                    await self._run_xdotool(
                        'keyup', '--clearmodifiers', '--window', target_window, key, timeout=0.5
                    )
                    logger.warning(f"Released stuck key after failure: {command} (key: {key})")
                except Exception as release_err:
                    logger.error(f"Failed to release stuck key {key}: {release_err}")"""

assert old2 in content, "old2 block not found"
content = content.replace(old2, new2)

with open(path, "w") as f:
    f.write(content)
print("patched")
