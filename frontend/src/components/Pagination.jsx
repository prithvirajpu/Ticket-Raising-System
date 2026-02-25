import React from 'react'

const Pagination = ({
  currentPage,
  totalPages,
  onPageChange,
  hasNext,
  hasPrevious
}) => {
  return (
    <div className="mt-8 flex justify-center items-center gap-2">

      <button
        disabled={!hasPrevious}
        onClick={() => onPageChange(currentPage - 1)}
        className="px-3 py-1 border rounded disabled:opacity-50"
      >
        &lt;
      </button>

      {Array.from({ length: totalPages }, (_, i) => (
        <button
          key={i}
          onClick={() => onPageChange(i + 1)}
          className={`w-8 h-8 flex items-center justify-center rounded 
          ${currentPage === i + 1
            ? 'bg-black text-white'
            : 'border hover:bg-gray-100'}`}
        >
          {i + 1}
        </button>
      ))}

      <button
        disabled={!hasNext}
        onClick={() => onPageChange(currentPage + 1)}
        className="px-3 py-1 border rounded disabled:opacity-50"
      >
        &gt;
      </button>

    </div>
  )
}

export default Pagination