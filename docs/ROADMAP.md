# nxtsOS Roadmap

Phases are sequential and each must end with a booting, tested image.
A phase is not "done" because code was written; it is done when its test
report is in `releases/`.

- [x] Phase 1 — Environment and architecture (this document set, build system)
- [x] Phase 2 — First bootable image: Multiboot kernel, console, PMM, interrupts
- [ ] Phase 3 — Kernel fundamentals: paging, scheduler, processes, syscalls,
      user/kernel ring separation
- [ ] Phase 4 — Graphics and input: VESA/framebuffer, font rendering,
      mouse, widgets, window manager
- [ ] Phase 5 — First desktop release: taskbar, launcher, windows, settings
      app, one functional GUI application
- [ ] Phase 6 — Persistent storage: ATA driver, VFS, filesystem, persistent
      settings, reboot-persistence test
- [ ] Phase 7 — Networking: virtual Ethernet (e1000/virtio-net), DHCP, DNS,
      TCP/UDP, sockets, TLS, guest-side connectivity test
- [ ] Phase 8 — Modern desktop: themes, workspaces, snapping, notifications,
      low-resource mode
- [ ] Phase 9 — Applications and security: file manager, terminal, editor,
      calculator, monitor, image viewer, network manager, browser (honest
      scope), permissions, package-management design
- [ ] Phase 10 — Verified releases: archives, checksums, VM guide, and
      (only with explicit authorisation) remote publishing per release

Current release: **v0.1.0 = end of Phase 2**.
