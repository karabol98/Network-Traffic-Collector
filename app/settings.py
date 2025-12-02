LOGGING_CONFIG = { 
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': { 
        'standard': { 
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
        'custom_formatter': { 
            'format': "%(asctime)s | %(levelname)s | %(filename)s:%(funcName)s:%(lineno)d | %(message)s | %(exc_info)s"
            
        },
    },
    'handlers': { 
        'default': { 
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',  # Default is stderr
        },
        'stream_handler': { 
            'formatter': 'custom_formatter',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',  # Default is stderr
        },
        'file_handler': { 
            'formatter': 'custom_formatter',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'app.log',
            'maxBytes': 1024 * 1024 * 1, # = 1MB
            'backupCount': 3,
        },
    },
    'loggers': { 
        'uvicorn': {
            'handlers': ['stream_handler'],
            'level': 'TRACE',
            'propagate': False
        },
        'uvicorn.access': {
            'handlers': ['stream_handler'],
            'level': 'TRACE',
            'propagate': False
        },
        'uvicorn.error': { 
            'handlers': ['stream_handler'],
            'level': 'TRACE',
            'propagate': False
        },
        'uvicorn.asgi': {
            'handlers': ['stream_handler'],
            'level': 'TRACE',
            'propagate': False
        },

    },
}