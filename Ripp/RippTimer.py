# Totally jacked this from:
# https://stackoverflow.com/questions/45419723/python-timer-with-asyncio-coroutine
# I had to urgently switch to asyncio.
import asyncio


class RippTimer:
    def __init__(self, timeout, callback, **kwargs):
        self._timeout = timeout
        self._callback = callback
        self._task = asyncio.ensure_future(self._job(**kwargs))

    async def _job(self,**kwargs):
        await asyncio.sleep(self._timeout)
        await self._callback(**kwargs)
    def cancel(self):
        self._task.cancel()
    
    def _started(self):
        if not self._task.done():
            return True
        return False

# async def timeout_callback():
#     await asyncio.sleep(0.1)
#     print('echo!')


# async def main():
#     print('\nfirst example:')
#     timer = Timer(2, timeout_callback)  # set timer for two seconds
#     await asyncio.sleep(2.5)  # wait to see timer works
# 
#     print('\nsecond example:')
#     timer = Timer(2, timeout_callback)  # set timer for two seconds
#     await asyncio.sleep(1)
#     timer.cancel()  # cancel it
#     await asyncio.sleep(1.5)  # and wait to see it won't call callback
# 
# 
# loop = asyncio.new_event_loop()
# asyncio.set_event_loop(loop)
# try:
#     loop.run_until_complete(main())
# finally:
#     loop.run_until_complete(loop.shutdown_asyncgens())
#     loop.close()