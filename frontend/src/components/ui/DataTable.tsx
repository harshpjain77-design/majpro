import React from 'react';
import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react';
import { EmptyState } from './EmptyState';

export interface Column<T> {
  key: string;
  header: string;
  render: (item: T) => React.ReactNode;
  sortable?: boolean;
  width?: string;
  align?: 'left' | 'center' | 'right';
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (item: T) => string;
  onRowClick?: (item: T) => void;
  sortColumn?: string;
  sortDirection?: 'asc' | 'desc';
  onSort?: (column: string) => void;
  emptyMessage?: string;
  loading?: boolean;
  compact?: boolean;
  className?: string;
}

export function DataTable<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  sortColumn,
  sortDirection,
  onSort,
  emptyMessage = 'No records found',
  loading = false,
  compact = false,
  className = ''
}: DataTableProps<T>): React.ReactElement {
  const [hoveredRowId, setHoveredRowId] = React.useState<string | null>(null);

  const cellPadding = compact ? '8px 12px' : '12px 16px';
  const headerPadding = compact ? '9px 12px' : '12px 16px';
  const fontSize = compact ? '0.75rem' : '0.8125rem';

  return (
    <div
      className={`threatgrid-data-table-container ${className}`}
      style={{
        width: '100%',
        overflowX: 'auto',
        backgroundColor: '#111827',
        border: '1px solid rgba(255, 255, 255, 0.06)',
        borderRadius: '8px',
        position: 'relative',
        scrollbarWidth: 'thin'
      }}
    >
      <table
        style={{
          width: '100%',
          borderCollapse: 'collapse',
          textAlign: 'left',
          fontSize,
          color: '#f9fafb'
        }}
      >
        {/* Table Header */}
        <thead>
          <tr
            style={{
              backgroundColor: '#161f30',
              borderBottom: '1px solid rgba(255, 255, 255, 0.08)'
            }}
          >
            {columns.map((column) => {
              const isSorted = sortColumn === column.key;
              const isSortable = !!column.sortable && !!onSort;

              return (
                <th
                  key={column.key}
                  onClick={() => {
                    if (isSortable && onSort) {
                      onSort(column.key);
                    }
                  }}
                  style={{
                    padding: headerPadding,
                    width: column.width || 'auto',
                    textAlign: column.align || 'left',
                    fontSize: compact ? '0.6875rem' : '0.75rem',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    color: isSorted ? '#60a5fa' : '#9ca3af',
                    cursor: isSortable ? 'pointer' : 'default',
                    userSelect: 'none',
                    position: 'sticky',
                    top: 0,
                    zIndex: 10,
                    backgroundColor: '#161f30',
                    transition: 'color 0.15s ease'
                  }}
                >
                  <div
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      justifyContent:
                        column.align === 'right'
                          ? 'flex-end'
                          : column.align === 'center'
                          ? 'center'
                          : 'flex-start'
                    }}
                  >
                    <span>{column.header}</span>
                    {isSortable && (
                      <span style={{ display: 'inline-flex', alignItems: 'center' }}>
                        {isSorted ? (
                          sortDirection === 'asc' ? (
                            <ChevronUp size={14} color="#3b82f6" strokeWidth={2.5} />
                          ) : (
                            <ChevronDown size={14} color="#3b82f6" strokeWidth={2.5} />
                          )
                        ) : (
                          <ChevronsUpDown size={13} color="#6b7280" />
                        )}
                      </span>
                    )}
                  </div>
                </th>
              );
            })}
          </tr>
        </thead>

        {/* Table Body */}
        <tbody>
          {/* Loading Skeleton */}
          {loading && (
            <>
              {Array.from({ length: compact ? 6 : 5 }).map((_, rIdx) => (
                <tr
                  key={`skeleton-${rIdx}`}
                  style={{
                    borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                    backgroundColor: rIdx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.015)'
                  }}
                >
                  {columns.map((col, cIdx) => (
                    <td key={`skeleton-cell-${cIdx}`} style={{ padding: cellPadding }}>
                      <div
                        style={{
                          height: compact ? '16px' : '20px',
                          width: `${55 + ((rIdx + cIdx) % 4) * 12}%`,
                          borderRadius: '4px',
                          background:
                            'linear-gradient(90deg, rgba(255, 255, 255, 0.03) 25%, rgba(255, 255, 255, 0.08) 50%, rgba(255, 255, 255, 0.03) 75%)',
                          backgroundSize: '200% 100%',
                          animation: 'tgShimmer 1.8s infinite ease-in-out'
                        }}
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </>
          )}

          {/* Empty State */}
          {!loading && data.length === 0 && (
            <tr>
              <td
                colSpan={columns.length}
                style={{
                  padding: '32px 16px',
                  textAlign: 'center'
                }}
              >
                <EmptyState
                  title={emptyMessage}
                  description="Try adjusting filters or checking back later."
                  compact={compact}
                />
              </td>
            </tr>
          )}

          {/* Data Rows */}
          {!loading &&
            data.length > 0 &&
            data.map((item, index) => {
              const rowKey = keyExtractor(item);
              const isHovered = hoveredRowId === rowKey;
              const isEven = index % 2 === 0;

              return (
                <tr
                  key={rowKey}
                  onClick={() => onRowClick && onRowClick(item)}
                  onMouseEnter={() => setHoveredRowId(rowKey)}
                  onMouseLeave={() => setHoveredRowId(null)}
                  style={{
                    backgroundColor: isHovered
                      ? 'rgba(59, 130, 246, 0.08)'
                      : isEven
                      ? 'transparent'
                      : 'rgba(255, 255, 255, 0.015)',
                    borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                    cursor: onRowClick ? 'pointer' : 'default',
                    transition: 'background-color 0.12s ease'
                  }}
                >
                  {columns.map((column) => (
                    <td
                      key={`${rowKey}-${column.key}`}
                      style={{
                        padding: cellPadding,
                        textAlign: column.align || 'left',
                        verticalAlign: 'middle',
                        color: isHovered ? '#ffffff' : '#e5e7eb'
                      }}
                    >
                      {column.render(item)}
                    </td>
                  ))}
                </tr>
              );
            })}
        </tbody>
      </table>
    </div>
  );
}
