const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "git2",
        .target = target,
        .optimize = optimize,
    });

    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    try flags.appendSlice(&.{
        "-DLIBGIT2_NO_FEATURES_H",
        "-DGIT_TRACE=1",
        "-DGIT_THREADS=1",
        "-DGIT_USE_FUTIMENS=1",
        "-DGIT_REGEX_PCRE",
        "-DGIT_SSH=1",
        "-DGIT_SSH_MEMORY_CREDENTIALS=1",
        "-DGIT_HTTPS=1",
        "-DGIT_MBEDTLS=1",
        "-DGIT_SHA1_MBEDTLS=1",
        "-fno-sanitize=all",
    });

    if (target.result.ptrBitWidth() == 64)
        try flags.append("-DGIT_ARCH_64=1");

    lib.addCSourceFiles(.{ .files = srcs, .flags = flags.items });
    if (target.result.os.tag == .windows) {
        try flags.appendSlice(&.{
            "-DGIT_WIN32",
            "-DGIT_WINHTTP",
        });
        lib.addCSourceFiles(.{ .files = win32_srcs, .flags = flags.items });

        if (target.result.isGnu()) {
            lib.addCSourceFiles(.{ .files = posix_srcs, .flags = flags.items });
            lib.addCSourceFiles(.{ .files = unix_srcs, .flags = flags.items });
        }
    } else {
        lib.addCSourceFiles(.{ .files = posix_srcs, .flags = flags.items });
        lib.addCSourceFiles(.{ .files = unix_srcs, .flags = flags.items });
    }

    if (target.result.os.tag == .linux)
        try flags.appendSlice(&.{
            "-DGIT_USE_NSEC=1",
            "-DGIT_USE_STAT_MTIM=1",
        });

    lib.addCSourceFiles(.{ .files = pcre_srcs, .flags = &.{
        "-DLINK_SIZE=2",
        "-DNEWLINE=10",
        "-DPOSIX_MALLOC_THRESHOLD=10",
        "-DMATCH_LIMIT_RECURSION=MATCH_LIMIT",
        "-DPARENS_NEST_LIMIT=250",
        "-DMATCH_LIMIT=10000000",
        "-DMAX_NAME_SIZE=32",
        "-DMAX_NAME_COUNT=10000",
    } });

    lib.addIncludePath(.{ .path = "libgit2/include" });
    lib.addIncludePath(.{ .path = "libgit2/src" });
    lib.addIncludePath(.{ .path = "libgit2/deps/pcre" });
    lib.addIncludePath(.{ .path = "libgit2/deps/http-parser" });
    lib.linkLibC();

    const mbedtls = b.dependency("mbedtls", .{ .target = target, .optimize = optimize });
    lib.linkLibrary(mbedtls.artifact("mbedtls"));

    const zlib = b.dependency("zlib", .{ .target = target, .optimize = optimize });
    lib.linkLibrary(zlib.artifact("z"));

    const ssh2 = b.dependency("ssh2", .{ .target = target, .optimize = optimize });
    lib.linkLibrary(ssh2.artifact("ssh2"));

    lib.installHeadersDirectory(.{ .path = "libgit2/include" }, "", .{});

    b.installArtifact(lib);

    const test_step = b.step("test", "Run tests");
    _ = test_step;
}

const srcs = &.{
    "libgit2/deps/http-parser/http_parser.c",
    "libgit2/src/allocators/failalloc.c",
    "libgit2/src/allocators/stdalloc.c",
    "libgit2/src/streams/openssl.c",
    "libgit2/src/streams/registry.c",
    "libgit2/src/streams/socket.c",
    "libgit2/src/streams/tls.c",
    "mbedtls.c",
    "libgit2/src/transports/auth.c",
    "libgit2/src/transports/credential.c",
    "libgit2/src/transports/http.c",
    "libgit2/src/transports/httpclient.c",
    "libgit2/src/transports/smart_protocol.c",
    "libgit2/src/transports/ssh.c",
    "libgit2/src/transports/git.c",
    "libgit2/src/transports/smart.c",
    "libgit2/src/transports/smart_pkt.c",
    "libgit2/src/transports/local.c",
    "libgit2/src/xdiff/xdiffi.c",
    "libgit2/src/xdiff/xemit.c",
    "libgit2/src/xdiff/xhistogram.c",
    "libgit2/src/xdiff/xmerge.c",
    "libgit2/src/xdiff/xpatience.c",
    "libgit2/src/xdiff/xprepare.c",
    "libgit2/src/xdiff/xutils.c",
    "libgit2/src/hash/sha1/mbedtls.c",
    "libgit2/src/alloc.c",
    "libgit2/src/annotated_commit.c",
    "libgit2/src/apply.c",
    "libgit2/src/attr.c",
    "libgit2/src/attrcache.c",
    "libgit2/src/attr_file.c",
    "libgit2/src/blame.c",
    "libgit2/src/blame_git.c",
    "libgit2/src/blob.c",
    "libgit2/src/branch.c",
    "libgit2/src/buffer.c",
    "libgit2/src/cache.c",
    "libgit2/src/checkout.c",
    "libgit2/src/cherrypick.c",
    "libgit2/src/clone.c",
    "libgit2/src/commit.c",
    "libgit2/src/commit_graph.c",
    "libgit2/src/commit_list.c",
    "libgit2/src/config.c",
    "libgit2/src/config_cache.c",
    "libgit2/src/config_entries.c",
    "libgit2/src/config_file.c",
    "libgit2/src/config_mem.c",
    "libgit2/src/config_parse.c",
    "libgit2/src/config_snapshot.c",
    "libgit2/src/crlf.c",
    "libgit2/src/date.c",
    "libgit2/src/delta.c",
    "libgit2/src/describe.c",
    "libgit2/src/diff.c",
    "libgit2/src/diff_driver.c",
    "libgit2/src/diff_file.c",
    "libgit2/src/diff_generate.c",
    "libgit2/src/diff_parse.c",
    "libgit2/src/diff_print.c",
    "libgit2/src/diff_stats.c",
    "libgit2/src/diff_tform.c",
    "libgit2/src/diff_xdiff.c",
    "libgit2/src/errors.c",
    "libgit2/src/email.c",
    "libgit2/src/fetch.c",
    "libgit2/src/fetchhead.c",
    "libgit2/src/filebuf.c",
    "libgit2/src/filter.c",
    "libgit2/src/futils.c",
    "libgit2/src/graph.c",
    "libgit2/src/hash.c",
    "libgit2/src/hashsig.c",
    "libgit2/src/ident.c",
    "libgit2/src/idxmap.c",
    "libgit2/src/ignore.c",
    "libgit2/src/index.c",
    "libgit2/src/indexer.c",
    "libgit2/src/iterator.c",
    "libgit2/src/libgit2.c",
    "libgit2/src/mailmap.c",
    "libgit2/src/merge.c",
    "libgit2/src/merge_driver.c",
    "libgit2/src/merge_file.c",
    "libgit2/src/message.c",
    "libgit2/src/midx.c",
    "libgit2/src/mwindow.c",
    "libgit2/src/net.c",
    "libgit2/src/netops.c",
    "libgit2/src/notes.c",
    "libgit2/src/object_api.c",
    "libgit2/src/object.c",
    "libgit2/src/odb.c",
    "libgit2/src/odb_loose.c",
    "libgit2/src/odb_mempack.c",
    "libgit2/src/odb_pack.c",
    "libgit2/src/offmap.c",
    "libgit2/src/oidarray.c",
    "libgit2/src/oid.c",
    "libgit2/src/oidmap.c",
    "libgit2/src/pack.c",
    "libgit2/src/pack-objects.c",
    "libgit2/src/parse.c",
    "libgit2/src/patch.c",
    "libgit2/src/patch_generate.c",
    "libgit2/src/patch_parse.c",
    "libgit2/src/path.c",
    "libgit2/src/pathspec.c",
    "libgit2/src/pool.c",
    "libgit2/src/pqueue.c",
    "libgit2/src/proxy.c",
    "libgit2/src/push.c",
    "libgit2/src/reader.c",
    "libgit2/src/rebase.c",
    "libgit2/src/refdb.c",
    "libgit2/src/refdb_fs.c",
    "libgit2/src/reflog.c",
    "libgit2/src/refs.c",
    "libgit2/src/refspec.c",
    "libgit2/src/regexp.c",
    "libgit2/src/remote.c",
    "libgit2/src/repository.c",
    "libgit2/src/reset.c",
    "libgit2/src/revert.c",
    "libgit2/src/revparse.c",
    "libgit2/src/revwalk.c",
    "libgit2/src/runtime.c",
    "libgit2/src/signature.c",
    "libgit2/src/sortedcache.c",
    "libgit2/src/stash.c",
    "libgit2/src/status.c",
    "libgit2/src/strarray.c",
    "libgit2/src/strmap.c",
    "libgit2/src/submodule.c",
    "libgit2/src/sysdir.c",
    "libgit2/src/tag.c",
    "libgit2/src/thread.c",
    "libgit2/src/threadstate.c",
    "libgit2/src/trace.c",
    "libgit2/src/trailer.c",
    "libgit2/src/transaction.c",
    "libgit2/src/transport.c",
    "libgit2/src/tree.c",
    "libgit2/src/tree-cache.c",
    "libgit2/src/tsort.c",
    "libgit2/src/utf8.c",
    "libgit2/src/util.c",
    "libgit2/src/varint.c",
    "libgit2/src/vector.c",
    "libgit2/src/wildmatch.c",
    "libgit2/src/worktree.c",
    "libgit2/src/zstream.c",
};

const pcre_srcs = &.{
    "libgit2/deps/pcre/pcre_byte_order.c",
    "libgit2/deps/pcre/pcre_chartables.c",
    "libgit2/deps/pcre/pcre_compile.c",
    "libgit2/deps/pcre/pcre_config.c",
    "libgit2/deps/pcre/pcre_dfa_exec.c",
    "libgit2/deps/pcre/pcre_exec.c",
    "libgit2/deps/pcre/pcre_fullinfo.c",
    "libgit2/deps/pcre/pcre_get.c",
    "libgit2/deps/pcre/pcre_globals.c",
    "libgit2/deps/pcre/pcre_jit_compile.c",
    "libgit2/deps/pcre/pcre_maketables.c",
    "libgit2/deps/pcre/pcre_newline.c",
    "libgit2/deps/pcre/pcre_ord2utf8.c",
    "libgit2/deps/pcre/pcreposix.c",
    "libgit2/deps/pcre/pcre_printint.c",
    "libgit2/deps/pcre/pcre_refcount.c",
    "libgit2/deps/pcre/pcre_string_utils.c",
    "libgit2/deps/pcre/pcre_study.c",
    "libgit2/deps/pcre/pcre_tables.c",
    "libgit2/deps/pcre/pcre_ucd.c",
    "libgit2/deps/pcre/pcre_valid_utf8.c",
    "libgit2/deps/pcre/pcre_version.c",
    "libgit2/deps/pcre/pcre_xclass.c",
};

const posix_srcs = &.{
    "libgit2/src/posix.c",
};

const unix_srcs = &.{
    "libgit2/src/unix/map.c",
    "libgit2/src/unix/realpath.c",
};

const win32_srcs = &.{
    "libgit2/src/win32/dir.c",
    "libgit2/src/win32/error.c",
    "libgit2/src/win32/findfile.c",
    "libgit2/src/win32/map.c",
    "libgit2/src/win32/path_w32.c",
    "libgit2/src/win32/posix_w32.c",
    "libgit2/src/win32/precompiled.c",
    "libgit2/src/win32/thread.c",
    "libgit2/src/win32/utf-conv.c",
    "libgit2/src/win32/w32_buffer.c",
    "libgit2/src/win32/w32_leakcheck.c",
    "libgit2/src/win32/w32_util.c",
};
