import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import api from '../../api/axios'
import Pagination from '../../components/Pagination'
import { getUserData } from '../../services/ticketService'

const UserManagement = () => {

  const [users, setUsers] = useState([])

  const [totalUsers, setTotalUsers] = useState(0)
  const [activeUsers, setActiveUsers] = useState(0)
  const [inactiveUsers, setInactiveUsers] = useState(0)

  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)

  const [nextPage, setNextPage] = useState(null)
  const [previousPage, setPreviousPage] = useState(null)

  useEffect(() => {
    fetchUsers(currentPage)
  }, [currentPage])

const fetchUsers = async (page = 1) => {

  try {

    const res = await getUserData(page)

    console.log(res)

    const data = res.data.data.message

    const paginator = res.data.paginator || {}

    setUsers(data.users)

    setTotalUsers(data.total_users)

    setActiveUsers(data.active_users)

    setInactiveUsers(data.inactive_users)

    setNextPage(paginator.next || null)

    setPreviousPage(paginator.previous || null)

    setTotalPages(
      Math.ceil(
        (paginator.count || 0) /
        (paginator.page_size || 5)
      )
    )
    console.log(totalPages)

  } catch (error) {

    console.error('Error fetching users:', error)

  }
}
  return (

    <DashboardLayout title="User Management">

      {/* HEADER */}

      <div className="mb-6">

        <h2 className="text-2xl font-bold">
          All Users
        </h2>

      </div>

      {/* STATS */}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">

        <StatsCard
          label="Total Users"
          value={totalUsers}
        />

        <StatsCard
          label="Active Users"
          value={activeUsers}
        />

        <StatsCard
          label="Inactive Users"
          value={inactiveUsers}
        />

      </div>

      {/* TABLE */}

      <div className="bg-white shadow rounded-lg overflow-hidden">

        <table className="w-full border-collapse">

          <thead className="bg-gray-100">

            <tr>

              <th className="p-3 text-left text-sm font-semibold text-gray-600">
                Index
              </th>

              <th className="p-3 text-left text-sm font-semibold text-gray-600">
                Name
              </th>

              <th className="p-3 text-left text-sm font-semibold text-gray-600">
                Email
              </th>

              <th className="p-3 text-left text-sm font-semibold text-gray-600">
                Phone
              </th>
              <th className="p-3 text-left text-sm font-semibold text-gray-600">
                Client
              </th>

              <th className="p-3 text-left text-sm font-semibold text-gray-600">
                Status
              </th>

            </tr>

          </thead>

          <tbody>

            {users.length === 0 ? (

              <tr>

                <td
                  colSpan="6"
                  className="text-center p-6 text-gray-500"
                >
                  No users found
                </td>

              </tr>

            ) : (

              users.map((user, index) => {

                const pageSize = 5

                const serialNumber =
                  (currentPage - 1) * pageSize + index + 1

                return (

                  <tr
                    key={user.id}
                    className="border-t hover:bg-gray-50"
                  >

                    <td className="p-3 text-sm">
                      {serialNumber}
                    </td>

                    <td className="p-3 text-sm font-medium">
                      {
                        user.name ||
                        user.email.split('@')[0]
                      }
                    </td>

                    <td className="p-3 text-sm text-gray-600">
                      {user.email}
                    </td>

                    <td className="p-3 text-sm text-gray-600">
                      {user.phone}
                    </td>
                    <td className="p-3 text-sm text-gray-600">
                      {user.client_name || 'N/A'}
                    </td>

                    <td className="p-3 text-sm">

                      {user.is_active ? (

                        <span className="text-green-600 font-medium">
                          Active
                        </span>

                      ) : (

                        <span className="text-red-600 font-medium">
                          Disabled
                        </span>

                      )}

                    </td>

                  </tr>

                )
              })

            )}

          </tbody>

        </table>

      </div>

      {/* PAGINATION */}

      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        onPageChange={setCurrentPage}
        hasNext={!!nextPage}
        hasPrevious={!!previousPage}
      />

    </DashboardLayout>
  )
}

export default UserManagement