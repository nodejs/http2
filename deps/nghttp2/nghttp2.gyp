{
  'target_defaults': {
    'defines': [
      '_U_='
    ]
  },
  'targets': [
    {
      'target_name': 'nghttp2',
      'type': '<(library)',
      'include_dirs': ['lib/includes'],
      'conditions': [
        ['debug_nghttp2 == 1', {
          'defines': [ 'DEBUGBUILD=1' ]
        }]
      ],
      'direct_dependent_settings': {
        'include_dirs': [ 'lib/includes' ]
      },
      'sources': [
        'lib/includes/nghttp2/nghttp2ver.h',
        'lib/includes/nghttp2/nghttp2.h',
        'lib/nghttp2_buf.c',
        'lib/nghttp2_buf.h',
        'lib/nghttp2_callbacks.c',
        'lib/nghttp2_callbacks.h',
        'lib/nghttp2_frame.c',
        'lib/nghttp2_frame.h',
        'lib/nghttp2_hd.c',
        'lib/nghttp2_hd.h',
        'lib/nghttp2_hd_huffman_data.c',
        'lib/nghttp2_hd_huffman.c',
        'lib/nghttp2_hd_huffman.h',
        'lib/nghttp2_helper.c',
        'lib/nghttp2_helper.h',
        'lib/nghttp2_http.c',
        'lib/nghttp2_http.h',
        'lib/nghttp2_int.h',
        'lib/nghttp2_map.c',
        'lib/nghttp2_map.h',
        'lib/nghttp2_mem.c',
        'lib/nghttp2_mem.h',
        'lib/nghttp2_net.h',
        'lib/nghttp2_npn.c',
        'lib/nghttp2_npn.h',
        'lib/nghttp2_option.c',
        'lib/nghttp2_option.h',
        'lib/nghttp2_outbound_item.c',
        'lib/nghttp2_outbound_item.h',
        'lib/nghttp2_pq.c',
        'lib/nghttp2_pq.h',
        'lib/nghttp2_priority_spec.c',
        'lib/nghttp2_priority_spec.h',
        'lib/nghttp2_queue.c',
        'lib/nghttp2_queue.h',
        'lib/nghttp2_rcbuf.c',
        'lib/nghttp2_rcbuf.h',
        'lib/nghttp2_session.c',
        'lib/nghttp2_session.h',
        'lib/nghttp2_stream.c',
        'lib/nghttp2_stream.h',
        'lib/nghttp2_submit.c',
        'lib/nghttp2_submit.h',
        'lib/nghttp2_version.c'
      ]
    }
  ]
}
