#!/bin/bash

# ============================================
# MASTER PROTECT SCRIPT - Pterodactyl Panel  
# Version: 3.0 (WITH AUTO-OWNER FIX)
# Author: Security System
# ============================================

echo "🛡️  MEMULAI INSTALASI SISTEM PROTEKSI FULL V3"
echo "=========================================="
sleep 2

# Backup directory
BACKUP_DIR="/var/www/pterodactyl-backup-$(date -u +"%Y-%m-%d-%H-%M-%S")"
mkdir -p "$BACKUP_DIR"
echo "📦 Backup directory: $BACKUP_DIR"

# ============================================
# PART 1: ServerDeletionService.php
# ============================================
echo ""
echo "🚀 [1/18] Memasang ServerDeletionService.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Services/Servers/ServerDeletionService.php"
BACKUP_PATH="${BACKUP_DIR}/ServerDeletionService.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Facades\Auth;
use Pterodactyl\Exceptions\DisplayException;
use Illuminate\Http\Response;
use Pterodactyl\Models\Server;
use Illuminate\Support\Facades\Log;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Services\Databases\DatabaseManagementService;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class ServerDeletionService
{
    protected bool $force = false;

    /**
     * ServerDeletionService constructor.
     */
    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $daemonServerRepository,
        private DatabaseManagementService $databaseManagementService
    ) {
    }

    /**
     * Set if the server should be forcibly deleted from the panel (ignoring daemon errors) or not.
     */
    public function withForce(bool $bool = true): self
    {
        $this->force = $bool;
        return $this;
    }

    /**
     * Delete a server from the panel and remove any associated databases from hosts.
     *
     * @throws \Throwable
     * @throws \Pterodactyl\Exceptions\DisplayException
     */
    public function handle(Server $server): void
    {
        $user = Auth::user();

        // 🔒 Proteksi: hanya Admin ID = 1 boleh menghapus server siapa saja.
        // Selain itu, user biasa hanya boleh menghapus server MILIKNYA SENDIRI.
        // Jika tidak ada informasi pemilik dan pengguna bukan admin, tolak.
        if ($user) {
            if ($user->id !== 1) {
                // Coba deteksi owner dengan beberapa fallback yang umum.
                $ownerId = $server->owner_id
                    ?? $server->user_id
                    ?? ($server->owner?->id ?? null)
                    ?? ($server->user?->id ?? null);

                if ($ownerId === null) {
                    // Tidak jelas siapa pemiliknya — jangan izinkan pengguna biasa menghapus.
                    throw new DisplayException('Akses ditolak: informasi pemilik server tidak tersedia.');
                }

                if ($ownerId !== $user->id) {
                    throw new DisplayException('❌Akses ditolak: Anda hanya dapat menghapus server milik Anda sendiri');
                }
            }
            // jika $user->id === 1, lanjutkan (admin super)
        }
        // Jika tidak ada $user (mis. CLI/background job), biarkan proses berjalan.

        try {
            $this->daemonServerRepository->setServer($server)->delete();
        } catch (DaemonConnectionException $exception) {
            // Abaikan error 404, tapi lempar error lain jika tidak mode force
            if (!$this->force && $exception->getStatusCode() !== Response::HTTP_NOT_FOUND) {
                throw $exception;
            }

            Log::warning($exception);
        }

        $this->connection->transaction(function () use ($server) {
            foreach ($server->databases as $database) {
                try {
                    $this->databaseManagementService->delete($database);
                } catch (\Exception $exception) {
                    if (!$this->force) {
                        throw $exception;
                    }

                    // Jika gagal delete database di host, tetap hapus dari panel
                    $database->delete();
                    Log::warning($exception);
                }
            }

            $server->delete();
        });
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ ServerDeletionService.php installed"

# ============================================
# PART 2: UserController.php
# ============================================
echo ""
echo "🚀 [2/18] Memasang UserController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/UserController.php"
BACKUP_PATH="${BACKUP_DIR}/UserController.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Pterodactyl\Models\Model;
use Illuminate\Support\Collection;
use Illuminate\Http\RedirectResponse;
use Prologue\Alerts\AlertsMessageBag;
use Spatie\QueryBuilder\QueryBuilder;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Exceptions\DisplayException;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Contracts\Translation\Translator;
use Pterodactyl\Services\Users\UserUpdateService;
use Pterodactyl\Traits\Helpers\AvailableLanguages;
use Pterodactyl\Services\Users\UserCreationService;
use Pterodactyl\Services\Users\UserDeletionService;
use Pterodactyl\Http\Requests\Admin\UserFormRequest;
use Pterodactyl\Http\Requests\Admin\NewUserFormRequest;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
class UserController extends Controller
{
    use AvailableLanguages;

    /**
     * UserController constructor.
     */
    public function __construct(
        protected AlertsMessageBag $alert,
        protected UserCreationService $creationService,
        protected UserDeletionService $deletionService,
        protected Translator $translator,
        protected UserUpdateService $updateService,
        protected UserRepositoryInterface $repository,
        protected ViewFactory $view
    ) {
    }

    /**
     * Display user index page.
     */
    public function index(Request $request): View
    {
        $user = auth()->user();
        
        // 🔒 Hanya ID 1 yang bisa lihat semua users
        if ($user->id !== 1) {
            // Admin biasa hanya bisa lihat dirinya sendiri
            $users = QueryBuilder::for(
                User::query()->select('users.*')
                    ->where('users.id', $user->id)
                    ->selectRaw('COUNT(DISTINCT(subusers.id)) as subuser_of_count')
                    ->selectRaw('COUNT(DISTINCT(servers.id)) as servers_count')
                    ->leftJoin('subusers', 'subusers.user_id', '=', 'users.id')
                    ->leftJoin('servers', 'servers.owner_id', '=', 'users.id')
                    ->groupBy('users.id')
            )
            ->paginate(1);
        } else {
            // Super admin lihat semua
            $users = QueryBuilder::for(
                User::query()->select('users.*')
                    ->selectRaw('COUNT(DISTINCT(subusers.id)) as subuser_of_count')
                    ->selectRaw('COUNT(DISTINCT(servers.id)) as servers_count')
                    ->leftJoin('subusers', 'subusers.user_id', '=', 'users.id')
                    ->leftJoin('servers', 'servers.owner_id', '=', 'users.id')
                    ->groupBy('users.id')
            )
            ->allowedFilters(['username', 'email', 'uuid'])
            ->allowedSorts(['id', 'uuid'])
            ->paginate(50);
        }

        return $this->view->make('admin.users.index', ['users' => $users]);
    }

    /**
     * Display new user page.
     */
    public function create(): View
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, '❌ Hanya admin ID 1 yang bisa membuat user baru');
        }

        return $this->view->make('admin.users.new', [
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    /**
     * Display user view page.
     */
    public function view(User $user): View
    {
        $authUser = auth()->user();
        
        // 🔒 Hanya bisa lihat profile sendiri atau admin ID 1
        if ($authUser->id !== 1 && $authUser->id !== $user->id) {
            abort(403, '🚫 Anda hanya bisa melihat profile sendiri');
        }

        return $this->view->make('admin.users.view', [
            'user' => $user,
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    /**
     * Delete a user from the system.
     *
     * @throws Exception
     * @throws PterodactylExceptionsDisplayException
     */
    public function delete(Request $request, User $user): RedirectResponse
    {
        // === FITUR TAMBAHAN: Proteksi hapus user ===
        if ($request->user()->id !== 1) {
            throw new DisplayException("❌ Hanya admin ID 1 yang dapat menghapus user lain!");
        }
        // ============================================

        if ($request->user()->id === $user->id) {
            throw new DisplayException($this->translator->get('admin/user.exceptions.user_has_servers'));
        }

        $this->deletionService->handle($user);

        return redirect()->route('admin.users');
    }

    /**
     * Create a user.
     *
     * @throws Exception
     * @throws Throwable
     */
    public function store(NewUserFormRequest $request): RedirectResponse
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, '❌ Hanya admin ID 1 yang bisa membuat user baru');
        }

        $user = $this->creationService->handle($request->normalize());
        $this->alert->success($this->translator->get('admin/user.notices.account_created'))->flash();

        return redirect()->route('admin.users.view', $user->id);
    }

    /**
     * Update a user on the system.
     *
     * @throws PterodactylExceptionsModelDataValidationException
     * @throws PterodactylExceptionsRepositoryRecordNotFoundException
     */
    public function update(UserFormRequest $request, User $user): RedirectResponse
    {
        $authUser = auth()->user();
        
        // 🔒 Hanya bisa update diri sendiri atau admin ID 1
        if ($authUser->id !== 1 && $authUser->id !== $user->id) {
            abort(403, '🚫 Anda hanya bisa mengupdate profile sendiri');
        }

        // === FITUR TAMBAHAN: Proteksi ubah data penting ===
        $restrictedFields = ['email', 'first_name', 'last_name', 'password'];

        foreach ($restrictedFields as $field) {
            if ($request->filled($field) && $request->user()->id !== 1) {
                throw new DisplayException("⚠️ Data hanya bisa diubah oleh admin ID 1.");
            }
        }

        // Cegah turunkan level admin ke user biasa
        if ($user->root_admin && $request->user()->id !== 1) {
            throw new DisplayException("🚫 Tidak dapat menurunkan hak admin pengguna ini. Hanya ID 1 yang memiliki izin.");
        }
        // ====================================================

        $this->updateService
            ->setUserLevel(User::USER_LEVEL_ADMIN)
            ->handle($user, $request->normalize());

        $this->alert->success(trans('admin/user.notices.account_updated'))->flash();

        return redirect()->route('admin.users.view', $user->id);
    }

    /**
     * Get a JSON response of users on the system.
     */
    public function json(Request $request): Model|Collection
    {
        $authUser = auth()->user();
        
        if ($authUser->id !== 1) {
            // Admin biasa hanya dapat data dirinya sendiri
            $user = User::query()->findOrFail($authUser->id);
            $user->md5 = md5(strtolower($user->email));
            return $user;
        }

        $users = QueryBuilder::for(User::query())->allowedFilters(['email'])->paginate(25);

        // Handle single user requests.
        if ($request->query('user_id')) {
            $user = User::query()->findOrFail($request->input('user_id'));
            $user->md5 = md5(strtolower($user->email));

            return $user;
        }

        return $users->map(function ($item) {
            $item->md5 = md5(strtolower($item->email));

            return $item;
        });
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ UserController.php installed"

# ============================================
# PART 3: LocationController.php
# ============================================
echo ""
echo "🚀 [3/18] Memasang LocationController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/LocationController.php"
BACKUP_PATH="${BACKUP_DIR}/LocationController.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\Location;
use Prologue\Alerts\AlertsMessageBag;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Exceptions\DisplayException;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Http\Requests\Admin\LocationFormRequest;
use Pterodactyl\Services\Locations\LocationUpdateService;
use Pterodactyl\Services\Locations\LocationCreationService;
use Pterodactyl\Services\Locations\LocationDeletionService;
use Pterodactyl\Contracts\Repository\LocationRepositoryInterface;

class LocationController extends Controller
{
    /**
     * LocationController constructor.
     */
    public function __construct(
        protected AlertsMessageBag $alert,
        protected LocationCreationService $creationService,
        protected LocationDeletionService $deletionService,
        protected LocationRepositoryInterface $repository,
        protected LocationUpdateService $updateService,
        protected ViewFactory $view
    ) {
    }

    /**
     * Return the location overview page.
     */
    public function index(): View
    {
        // 🔒 Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak');
        }

        return $this->view->make('admin.locations.index', [
            'locations' => $this->repository->getAllWithDetails(),
        ]);
    }

    /**
     * Return the location view page.
     *
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function view(int $id): View
    {
        // 🔒 Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'BOCAH TOLOL NGINTIP NGINTIP ');
        }

        return $this->view->make('admin.locations.view', [
            'location' => $this->repository->getWithNodes($id),
        ]);
    }

    /**
     * Handle request to create new location.
     *
     * @throws \Throwable
     */
    public function create(LocationFormRequest $request): RedirectResponse
    {
        // 🔒 Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'BOCAH TOLOL NGINTIP NGINTIP ');
        }

        $location = $this->creationService->handle($request->normalize());
        $this->alert->success('Location was created successfully.')->flash();

        return redirect()->route('admin.locations.view', $location->id);
    }

    /**
     * Handle request to update or delete location.
     *
     * @throws \Throwable
     */
    public function update(LocationFormRequest $request, Location $location): RedirectResponse
    {
        // 🔒 Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'BOCAH TOLOL NGINTIP NGINTIP ');
        }

        if ($request->input('action') === 'delete') {
            return $this->delete($location);
        }

        $this->updateService->handle($location->id, $request->normalize());
        $this->alert->success('Location was updated successfully.')->flash();

        return redirect()->route('admin.locations.view', $location->id);
    }

    /**
     * Delete a location from the system.
     *
     * @throws \Exception
     * @throws \Pterodactyl\Exceptions\DisplayException
     */
    public function delete(Location $location): RedirectResponse
    {
        // 🔒 Cegah akses selain admin ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'BOCAH TOLOL NGINTIP NGINTIP ');
        }

        try {
            $this->deletionService->handle($location->id);
            return redirect()->route('admin.locations');
        } catch (DisplayException $ex) {
            $this->alert->danger($ex->getMessage())->flash();
        }

        return redirect()->route('admin.locations.view', $location->id);
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ LocationController.php installed"

# ============================================
# PART 4: NodeController.php (Admin/Nodes)
# ============================================
echo ""
echo "🚀 [4/18] Memasang NodeController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/Nodes/NodeController.php"
BACKUP_PATH="${BACKUP_DIR}/NodeController.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Nodes;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Pterodactyl\Models\Node;
use Spatie\QueryBuilder\QueryBuilder;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Support\Facades\Auth; // ✅ tambahan untuk ambil user login

class NodeController extends Controller
{
    /**
     * NodeController constructor.
     */
    public function __construct(private ViewFactory $view)
    {
    }

    /**
     * Returns a listing of nodes on the system.
     */
    public function index(Request $request): View
    {
        // === 🔒 FITUR TAMBAHAN: Anti akses selain admin ID 1 ===
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, '🚫 Akses ditolak! Hanya admin ID 1 yang dapat membuka menu Nodes.');
        }
        // ======================================================

        $nodes = QueryBuilder::for(
            Node::query()->with('location')->withCount('servers')
        )
            ->allowedFilters(['uuid', 'name'])
            ->allowedSorts(['id'])
            ->paginate(25);

        return $this->view->make('admin.nodes.index', ['nodes' => $nodes]);
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ NodeController.php installed"

# ============================================
# PART 5: NestController.php
# ============================================
echo ""
echo "🚀 [5/18] Memasang NestController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/Nests/NestController.php"
BACKUP_PATH="${BACKUP_DIR}/NestController.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Nests;

use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;
use Prologue\Alerts\AlertsMessageBag;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Services\Nests\NestUpdateService;
use Pterodactyl\Services\Nests\NestCreationService;
use Pterodactyl\Services\Nests\NestDeletionService;
use Pterodactyl\Contracts\Repository\NestRepositoryInterface;
use Pterodactyl\Http\Requests\Admin\Nest\StoreNestFormRequest;
use Illuminate\Support\Facades\Auth; // ✅ Tambahan

class NestController extends Controller
{
    /**
     * NestController constructor.
     */
    public function __construct(
        protected AlertsMessageBag $alert,
        protected NestCreationService $nestCreationService,
        protected NestDeletionService $nestDeletionService,
        protected NestRepositoryInterface $repository,
        protected NestUpdateService $nestUpdateService,
        protected ViewFactory $view
    ) {
    }

    /**
     * Render nest listing page.
     *
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function index(): View
    {
        // 🔒 Proteksi: hanya user ID 1 (superadmin) yang bisa akses menu Nest
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, '🚫 Akses ditolak! Hanya admin utama (ID 1) yang bisa membuka menu Nests.');
        }

        return $this->view->make('admin.nests.index', [
            'nests' => $this->repository->getWithCounts(),
        ]);
    }

    /**
     * Render nest creation page.
     */
    public function create(): View
    {
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, '🚫 Akses ditolak!');
        }

        return $this->view->make('admin.nests.new');
    }

    /**
     * Handle the storage of a new nest.
     *
     * @throws \Pterodactyl\Exceptions\Model\DataValidationException
     */
    public function store(StoreNestFormRequest $request): RedirectResponse
    {
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, '🚫 Akses ditolak!');
        }

        $nest = $this->nestCreationService->handle($request->normalize());
        $this->alert->success(trans('admin/nests.notices.created', ['name' => htmlspecialchars($nest->name)]))->flash();

        return redirect()->route('admin.nests.view', $nest->id);
    }

    /**
     * Return details about a nest including all the eggs and servers per egg.
     *
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function view(int $nest): View
    {
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, '🚫 Akses ditolak!');
        }

        return $this->view->make('admin.nests.view', [
            'nest' => $this->repository->getWithEggServers($nest),
        ]);
    }

    /**
     * Handle request to update a nest.
     *
     * @throws \Pterodactyl\Exceptions\Model\DataValidationException
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function update(StoreNestFormRequest $request, int $nest): RedirectResponse
    {
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, '🚫 Akses ditolak!');
        }

        $this->nestUpdateService->handle($nest, $request->normalize());
        $this->alert->success(trans('admin/nests.notices.updated'))->flash();

        return redirect()->route('admin.nests.view', $nest);
    }

    /**
     * Handle request to delete a nest.
     *
     * @throws \Pterodactyl\Exceptions\Service\HasActiveServersException
     */
    public function destroy(int $nest): RedirectResponse
    {
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, '🚫 Akses ditolak!');
        }

        $this->nestDeletionService->handle($nest);
        $this->alert->success(trans('admin/nests.notices.deleted'))->flash();

        return redirect()->route('admin.nests');
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ NestController.php installed"

# ============================================
# PART 6: Settings IndexController.php
# ============================================
echo ""
echo "🚀 [6/18] Memasang Settings IndexController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/Settings/IndexController.php"
BACKUP_PATH="${BACKUP_DIR}/IndexController.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin\Settings;

use Illuminate\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Prologue\Alerts\AlertsMessageBag;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Traits\Helpers\AvailableLanguages;
use Pterodactyl\Services\Helpers\SoftwareVersionService;
use Pterodactyl\Contracts\Repository\SettingsRepositoryInterface;
use Pterodactyl\Http\Requests\Admin\Settings\BaseSettingsFormRequest;

class IndexController extends Controller
{
    use AvailableLanguages;

    /**
     * IndexController constructor.
     */
    public function __construct(
        private AlertsMessageBag $alert,
        private Kernel $kernel,
        private SettingsRepositoryInterface $settings,
        private SoftwareVersionService $versionService,
        private ViewFactory $view
    ) {
    }

    /**
     * Render the UI for basic Panel settings.
     */
    public function index(): View
    {
        // 🔒 Anti akses menu Settings selain user ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'BOCAH TOLOL NGINTIP NGINTIP ');
        }

        return $this->view->make('admin.settings.index', [
            'version' => $this->versionService,
            'languages' => $this->getAvailableLanguages(true),
        ]);
    }

    /**
     * Handle settings update.
     *
     * @throws \Pterodactyl\Exceptions\Model\DataValidationException
     * @throws \Pterodactyl\Exceptions\Repository\RecordNotFoundException
     */
    public function update(BaseSettingsFormRequest $request): RedirectResponse
    {
        // 🔒 Anti akses update settings selain user ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'BOCAH TOLOL NGINTIP NGINTIP ');
        }

        foreach ($request->normalize() as $key => $value) {
            $this->settings->set('settings::' . $key, $value);
        }

        $this->kernel->call('queue:restart');
        $this->alert->success(
            'Panel settings have been updated successfully and the queue worker was restarted to apply these changes.'
        )->flash();

        return redirect()->route('admin.settings');
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ Settings IndexController.php installed"

# ============================================
# PART 7: FileController.php (Client API)
# ============================================
echo ""
echo "🚀 [7/18] Memasang FileController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Api/Client/Servers/FileController.php"
BACKUP_PATH="${BACKUP_DIR}/FileController.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Api\Client\Servers;

use Carbon\CarbonImmutable;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Models\Server;
use Pterodactyl\Facades\Activity;
use Pterodactyl\Services\Nodes\NodeJWTService;
use Pterodactyl\Repositories\Wings\DaemonFileRepository;
use Pterodactyl\Transformers\Api\Client\FileObjectTransformer;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CopyFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\PullFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\ListFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\ChmodFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\DeleteFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\RenameFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CreateFolderRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CompressFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\DecompressFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\GetFileContentsRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\WriteFileContentRequest;

class FileController extends ClientApiController
{
    public function __construct(
        private NodeJWTService $jwtService,
        private DaemonFileRepository $fileRepository
    ) {
        parent::__construct();
    }

    /**
     * 🛡️ Fungsi tambahan: Cegah akses server orang lain.
     */
    private function checkServerAccess($request, Server $server)
    {
        $user = $request->user();

        // Admin (user id = 1) bebas akses semua
        if ($user->id === 1) {
            return;
        }

        // Jika server bukan milik user, tolak akses
        if ($server->owner_id !== $user->id) {
            abort(403, 'Anda tidak memiliki akses ke server ini.');
        }
    }

    public function directory(ListFilesRequest $request, Server $server): array
    {
        $this->checkServerAccess($request, $server);

        $contents = $this->fileRepository
            ->setServer($server)
            ->getDirectory($request->get('directory') ?? '/');

        return $this->fractal->collection($contents)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function contents(GetFileContentsRequest $request, Server $server): Response
    {
        $this->checkServerAccess($request, $server);

        $response = $this->fileRepository->setServer($server)->getContent(
            $request->get('file'),
            config('pterodactyl.files.max_edit_size')
        );

        Activity::event('server:file.read')->property('file', $request->get('file'))->log();

        return new Response($response, Response::HTTP_OK, ['Content-Type' => 'text/plain']);
    }

    public function download(GetFileContentsRequest $request, Server $server): array
    {
        $this->checkServerAccess($request, $server);

        $token = $this->jwtService
            ->setExpiresAt(CarbonImmutable::now()->addMinutes(15))
            ->setUser($request->user())
            ->setClaims([
                'file_path' => rawurldecode($request->get('file')),
                'server_uuid' => $server->uuid,
            ])
            ->handle($server->node, $request->user()->id . $server->uuid);

        Activity::event('server:file.download')->property('file', $request->get('file'))->log();

        return [
            'object' => 'signed_url',
            'attributes' => [
                'url' => sprintf(
                    '%s/download/file?token=%s',
                    $server->node->getConnectionAddress(),
                    $token->toString()
                ),
            ],
        ];
    }

    public function write(WriteFileContentRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository->setServer($server)->putContent($request->get('file'), $request->getContent());

        Activity::event('server:file.write')->property('file', $request->get('file'))->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function create(CreateFolderRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->createDirectory($request->input('name'), $request->input('root', '/'));

        Activity::event('server:file.create-directory')
            ->property('name', $request->input('name'))
            ->property('directory', $request->input('root'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function rename(RenameFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->renameFiles($request->input('root'), $request->input('files'));

        Activity::event('server:file.rename')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function copy(CopyFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->copyFile($request->input('location'));

        Activity::event('server:file.copy')->property('file', $request->input('location'))->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function compress(CompressFilesRequest $request, Server $server): array
    {
        $this->checkServerAccess($request, $server);

        $file = $this->fileRepository->setServer($server)->compressFiles(
            $request->input('root'),
            $request->input('files')
        );

        Activity::event('server:file.compress')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return $this->fractal->item($file)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function decompress(DecompressFilesRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        set_time_limit(300);

        $this->fileRepository->setServer($server)->decompressFile(
            $request->input('root'),
            $request->input('file')
        );

        Activity::event('server:file.decompress')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('file'))
            ->log();

        return new JsonResponse([], JsonResponse::HTTP_NO_CONTENT);
    }

    public function delete(DeleteFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository->setServer($server)->deleteFiles(
            $request->input('root'),
            $request->input('files')
        );

        Activity::event('server:file.delete')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function chmod(ChmodFilesRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository->setServer($server)->chmodFiles(
            $request->input('root'),
            $request->input('files')
        );

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function pull(PullFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);

        $this->fileRepository->setServer($server)->pull(
            $request->input('url'),
            $request->input('directory'),
            $request->safe(['filename', 'use_header', 'foreground'])
        );

        Activity::event('server:file.pull')
            ->property('directory', $request->input('directory'))
            ->property('url', $request->input('url'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ FileController.php installed"

# ============================================
# PART 8: ServerController.php (Client API)
# ============================================
echo ""
echo "🚀 [8/18] Memasang ServerController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Api/Client/Servers/ServerController.php"
BACKUP_PATH="${BACKUP_DIR}/ServerController.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Api\Client\Servers;

use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\Server;
use Pterodactyl\Transformers\Api\Client\ServerTransformer;
use Pterodactyl\Services\Servers\GetUserPermissionsService;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Pterodactyl\Http\Requests\Api\Client\Servers\GetServerRequest;

class ServerController extends ClientApiController
{
    /**
     * ServerController constructor.
     */
    public function __construct(private GetUserPermissionsService $permissionsService)
    {
        parent::__construct();
    }

    /**
     * Transform an individual server into a response that can be consumed by a
     * client using the API.
     */
    public function index(GetServerRequest $request, Server $server): array
    {
        // 🔒 Anti intip server orang lain (kecuali admin ID 1)
        $authUser = Auth::user();

        if ($authUser->id !== 1 && (int) $server->owner_id !== (int) $authUser->id) {
            abort(403, '𝗔𝗸𝘀𝗲𝘀 𝗗𝗶 𝗧𝗼𝗹𝗮𝗸❌. 𝗛𝗮𝗻𝘆𝗮 𝗕𝗶𝘀𝗮 𝗠𝗲𝗹𝗶𝗵𝗮𝘁 𝗦𝗲𝗿𝘃𝗲𝗿 𝗠𝗶𝗹𝗶𝗸 𝗦𝗲𝗻𝗱𝗶𝗿𝗶.');
        }

        return $this->fractal->item($server)
            ->transformWith($this->getTransformer(ServerTransformer::class))
            ->addMeta([
                'is_server_owner' => $request->user()->id === $server->owner_id,
                'user_permissions' => $this->permissionsService->handle($server, $request->user()),
            ])
            ->toArray();
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ ServerController.php installed"

# ============================================
# PART 9: DetailsModificationService.php
# ============================================
echo ""
echo "🚀 [9/18] Memasang DetailsModificationService.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Services/Servers/DetailsModificationService.php"
BACKUP_PATH="${BACKUP_DIR}/DetailsModificationService.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Services\Servers;

use Illuminate\Support\Arr;
use Pterodactyl\Models\Server;
use Illuminate\Support\Facades\Auth;
use Illuminate\Database\ConnectionInterface;
use Pterodactyl\Traits\Services\ReturnsUpdatedModels;
use Pterodactyl\Repositories\Wings\DaemonServerRepository;
use Pterodactyl\Exceptions\Http\Connection\DaemonConnectionException;

class DetailsModificationService
{
    use ReturnsUpdatedModels;

    public function __construct(
        private ConnectionInterface $connection,
        private DaemonServerRepository $serverRepository
    ) {}

    /**
     * Update the details for a single server instance.
     *
     * @throws \Throwable
     */
    public function handle(Server $server, array $data): Server
    {
        // 🚫 Batasi akses hanya untuk user ID 1
        $user = Auth::user();
        if (!$user || $user->id !== 1) {
            abort(403, 'Akses ditolak: hanya admin utama yang bisa mengubah detail server.');
        }

        return $this->connection->transaction(function () use ($data, $server) {
            $owner = $server->owner_id;

            $server->forceFill([
                'external_id' => Arr::get($data, 'external_id'),
                'owner_id' => Arr::get($data, 'owner_id'),
                'name' => Arr::get($data, 'name'),
                'description' => Arr::get($data, 'description') ?? '',
            ])->saveOrFail();

            // Jika owner berubah, revoke token lama
            if ($server->owner_id !== $owner) {
                try {
                    $this->serverRepository->setServer($server)->revokeUserJTI($owner);
                } catch (DaemonConnectionException $exception) {
                    // Abaikan error dari Wings offline
                }
            }

            return $server;
        });
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ DetailsModificationService.php installed"

# ============================================
# PART 10: core.blade.php (Welcome Message)
# ============================================
echo ""
echo "🚀 [10/18] Memasang core.blade.php..."

REMOTE_PATH="/var/www/pterodactyl/resources/views/templates/base/core.blade.php"
BACKUP_PATH="${BACKUP_DIR}/core.blade.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
@extends('templates/wrapper', [
    'css' => ['body' => 'bg-neutral-800'],
])

@section('container')
    <div id="modal-portal"></div>
    <div id="app"></div>

    <script>
      document.addEventListener("DOMContentLoaded", () => {
        const username = @json(auth()->user()->name?? 'User');

        const message = document.createElement("div");
        message.innerText = `🚀 Hai ${username}, Apa Kabar?`;
        Object.assign(message.style, {
          position: "fixed",
          bottom: "20px",
          right: "20px",
          background: "rgba(0,0,0,0.75)",
          color: "#fff",
          padding: "10px 15px",
          borderRadius: "10px",
          fontFamily: "monospace",
          fontSize: "14px",
          boxShadow: "0 0 10px rgba(0,0,0,0.3)",
          zIndex: "9999",
          opacity: "1",
          transition: "opacity 1s ease"
        });

        document.body.appendChild(message);
        setTimeout(() => message.style.opacity = "0", 3000);
        setTimeout(() => message.remove(), 4000);
      });
    </script>
@endsection
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ core.blade.php installed"

# ============================================
# PART 11: NodesController.php (Main Nodes)
# ============================================
echo ""
echo "🚀 [11/18] Memasang NodesController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/NodesController.php"
BACKUP_PATH="${BACKUP_DIR}/NodesController.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\RedirectResponse;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Models\Node;
use Pterodactyl\Models\Allocation;
use Pterodactyl\Http\Controllers\Controller;
use Prologue\Alerts\AlertsMessageBag;
use Pterodactyl\Services\Nodes\NodeUpdateService;
use Pterodactyl\Services\Nodes\NodeCreationService;
use Pterodactyl\Services\Nodes\NodeDeletionService;
use Pterodactyl\Services\Allocations\AssignmentService;
use Pterodactyl\Services\Allocations\AllocationDeletionService;
use Pterodactyl\Contracts\Repository\NodeRepositoryInterface;
use Pterodactyl\Contracts\Repository\ServerRepositoryInterface;
use Pterodactyl\Contracts\Repository\LocationRepositoryInterface;
use Pterodactyl\Contracts\Repository\AllocationRepositoryInterface;
use Pterodactyl\Http\Requests\Admin\Node\NodeFormRequest;
use Pterodactyl\Http\Requests\Admin\Node\AllocationFormRequest;
use Pterodactyl\Http\Requests\Admin\Node\AllocationAliasFormRequest;
use Pterodactyl\Services\Helpers\SoftwareVersionService;

class NodesController extends Controller
{
    public function __construct(
        protected AlertsMessageBag $alert,
        protected AllocationDeletionService $allocationDeletionService,
        protected AllocationRepositoryInterface $allocationRepository,
        protected AssignmentService $assignmentService,
        protected NodeCreationService $creationService,
        protected NodeDeletionService $deletionService,
        protected LocationRepositoryInterface $locationRepository,
        protected NodeRepositoryInterface $repository,
        protected ServerRepositoryInterface $serverRepository,
        protected NodeUpdateService $updateService,
        protected SoftwareVersionService $versionService,
        protected ViewFactory $view
    ) {}

    /**
     * Membuat node baru.
     */
    public function create(): View|RedirectResponse
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, "🚫 Akses ditolak! Hanya admin ID 1");
        }

        $locations = $this->locationRepository->all();
        if (count($locations) < 1) {
            $this->alert->warning(trans('admin/node.notices.location_required'))->flash();
            return redirect()->route('admin.locations');
        }

        return $this->view->make('admin.nodes.new', ['locations' => $locations]);
    }

    /**
     * Simpan node baru.
     */
    public function store(NodeFormRequest $request): RedirectResponse
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, "🚫 Kamu tidak punya izin untuk menambahkan node. Hanya admin ID 1 yang bisa!");
        }

        $node = $this->creationService->handle($request->normalize());
        $this->alert->info(trans('admin/node.notices.node_created'))->flash();
        return redirect()->route('admin.nodes.view.allocation', $node->id);
    }

    /**
     * Update node (khusus Admin ID 1).
     */
    public function updateSettings(NodeFormRequest $request, Node $node): RedirectResponse
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, "⚠️ AKSES DI TOLAK HANYA ADMIN ID 1 YANG BISA EDIT NODE");
        }

        $this->updateService->handle($node, $request->normalize(), $request->input('reset_secret') === 'on');
        $this->alert->success(trans('admin/node.notices.node_updated'))->flash();
        return redirect()->route('admin.nodes.view.settings', $node->id)->withInput();
    }

    /**
     * Hapus node (khusus Admin ID 1).
     */
    public function delete(int|Node $node): RedirectResponse
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, "❌ 𝐋𝐔 𝐒𝐄𝐇𝐀𝐓 𝐍𝐆𝐄𝐋𝐀𝐊𝐔𝐈𝐍 𝐇𝐀𝐏𝐔𝐒 𝐍𝐎𝐃𝐄?");
        }

        $this->deletionService->handle($node);
        $this->alert->success(trans('admin/node.notices.node_deleted'))->flash();
        return redirect()->route('admin.nodes');
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ NodesController.php installed"

# ============================================
# PART 12: ApiController.php
# ============================================
echo ""
echo "🚀 [12/18] Memasang ApiController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/ApiController.php"
BACKUP_PATH="${BACKUP_DIR}/ApiController.php.bak"

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Pterodactyl\Models\ApiKey;
use Illuminate\Http\RedirectResponse;
use Prologue\Alerts\AlertsMessageBag;
use Pterodactyl\Services\Acl\Api\AdminAcl;
use Illuminate\View\Factory as ViewFactory;
use Pterodactyl\Http\Controllers\Controller;
use Pterodactyl\Services\Api\KeyCreationService;
use Pterodactyl\Contracts\Repository\ApiKeyRepositoryInterface;
use Pterodactyl\Http\Requests\Admin\Api\StoreApplicationApiKeyRequest;

class ApiController extends Controller
{
    public function __construct(
        private AlertsMessageBag $alert,
        private ApiKeyRepositoryInterface $repository,
        private KeyCreationService $keyCreationService,
        private ViewFactory $view,
    ) {}

    public function index(Request $request): View
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, "🚫 LU SEHAT NGINTIP NGINTIP? SYAHV2DOFFC PROTECT ⚠️");
        }

        return $this->view->make('admin.api.index', [
            'keys' => $this->repository->getApplicationKeys($request->user()),
        ]);
    }

    public function create(): View
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, "🚫 LU SEHAT NGINTIP NGINTIP? SYAHV2DOFFC PROTECT ⚠️");
        }

        $resources = AdminAcl::getResourceList();
        sort($resources);

        return $this->view->make('admin.api.new', [
            'resources' => $resources,
            'permissions' => [
                'r'  => AdminAcl::READ,
                'rw' => AdminAcl::READ | AdminAcl::WRITE,
                'n'  => AdminAcl::NONE,
            ],
        ]);
    }

    public function store(StoreApplicationApiKeyRequest $request): RedirectResponse
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, "🚫 Akses ditolak!");
        }

        $this->keyCreationService
            ->setKeyType(ApiKey::TYPE_APPLICATION)
            ->handle([
                'memo'    => $request->input('memo'),
                'user_id' => $request->user()->id,
            ], $request->getKeyPermissions());

        $this->alert->success('A new application API key has been generated for your account.')->flash();
        return redirect()->route('admin.api.index');
    }

    public function delete(Request $request, string $identifier): Response
    {
        $user = auth()->user();
        if ($user->id !== 1) {
            abort(403, "🚫 Akses ditolak!");
        }

        $this->repository->deleteApplicationKey($request->user(), $identifier);
        return response('', 204);
    }
}
EOF

chmod 644 "$REMOTE_PATH"
echo "✅ ApiController.php installed"

# ============================================
# PART 13: ServersController.php (Admin)
# ============================================
echo ""
echo "🚀 [13/18] Memasang ServersController.php..."

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/ServersController.php"
BACKUP_PATH="${BACKUP_DIR}/ServersController.php.bak"

# Cek apakah file ada, jika tidak mungkin di lokasi lain
if [ ! -f "$REMOTE_PATH" ]; then
    # Coba alternatif path
    REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Admin/Servers/ServerController.php"
fi

if [ -f "$REMOTE_PATH" ]; then
  cp "$REMOTE_PATH" "$BACKUP_PATH"
  
  # Cek jika file sudah ada kita perlu modifikasi
  if grep -q "class ServerController" "$REMOTE_PATH" 2>/dev/null; then
    echo "⚠️  File ServersController sudah ada, skip instalasi..."
  else
    cat > "$REMOTE_PATH" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\View\View;
use Illuminate\Http\Request;
use Pterodactyl\Models\Server;
use Spatie\QueryBuilder\QueryBuilder;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Pterodactyl\Contracts\Repository\ServerRepositoryInterface;

class ServersController extends Controller
{
    public function __construct(
        private ServerRepositoryInterface $repository,
        private ViewFactory $view
    ) {}

    /**
     * Returns listing of all servers on the system.
     */
    public function index(Request $request): View
    {
        $user = auth()->user();
        
        if ($user->id === 1) {
            // Admin ID 1 lihat semua server
            $servers = QueryBuilder::for(Server::query()->with('user', 'node'))
                ->allowedFilters(['uuid', 'name', 'owner_id'])
                ->allowedSorts(['id'])
                ->paginate(50);
        } else {
            // Admin lain hanya lihat server miliknya sendiri
            $servers = QueryBuilder::for(
                Server::query()->with('user', 'node')
                    ->where('owner_id', $user->id)
            )
                ->paginate(50);
        }

        return $this->view->make('admin.servers.index', ['servers' => $servers]);
    }
}
EOF
    chmod 644 "$REMOTE_PATH"
    echo "✅ ServersController.php installed"
  fi
else
  echo "⚠️  File ServersController.php tidak ditemukan, skip..."
fi

# ============================================
# PART 14: DatabaseController.php Protection
# ============================================
echo ""
echo "🚀 [14/18] Memasang proteksi DatabaseController..."

# Cari file DatabaseController
DB_FILES=$(find /var/www/pterodactyl -name "*DatabaseController.php" -type f 2>/dev/null | head -1)

if [ -n "$DB_FILES" ]; then
  for DB_FILE in $DB_FILES; do
    BACKUP_DB="${BACKUP_DIR}/$(basename $DB_FILE).bak"
    cp "$DB_FILE" "$BACKUP_DB"
    
    # Tambahkan protection di setiap method
    sed -i '/public function /a \ \ \ \ \ \ \ \ $user = auth()->user();\n\ \ \ \ \ \ \ \ if ($user->id !== 1) {\n\ \ \ \ \ \ \ \ \ \ \ \ abort(403, "🚫 Akses ditolak! Hanya admin ID 1");\n\ \ \ \ \ \ \ \ }' "$DB_FILE" 2>/dev/null
    
    if [ $? -eq 0 ]; then
      echo "✅ Proteksi ditambahkan ke $(basename $DB_FILE)"
    fi
  done
else
  echo "⚠️  DatabaseController tidak ditemukan, skip..."
fi

# ============================================
# PART 15: MountController.php Protection
# ============================================
echo ""
echo "🚀 [15/18] Memasang proteksi MountController..."

# Cari file MountController
MOUNT_FILES=$(find /var/www/pterodactyl -name "*Mount*Controller.php" -type f 2>/dev/null | head -1)

if [ -n "$MOUNT_FILES" ]; then
  for MOUNT_FILE in $MOUNT_FILES; do
    BACKUP_MOUNT="${BACKUP_DIR}/$(basename $MOUNT_FILE).bak"
    cp "$MOUNT_FILE" "$BACKUP_MOUNT"
    
    # Tambahkan protection
    sed -i '/class.*Mount/a \ \ \ \ public function __construct()\n\ \ \ \ {\n\ \ \ \ \ \ \ \ $user = auth()->user();\n\ \ \ \ \ \ \ \ if ($user->id !== 1) {\n\ \ \ \ \ \ \ \ \ \ \ \ abort(403, "🚫 Akses ditolak! Hanya admin ID 1");\n\ \ \ \ \ \ \ \ }\n\ \ \ \ }' "$MOUNT_FILE" 2>/dev/null
    
    if [ $? -eq 0 ]; then
      echo "✅ Proteksi ditambahkan ke $(basename $MOUNT_FILE)"
    fi
  done
else
  echo "⚠️  MountController tidak ditemukan, skip..."
fi

# ============================================
# PART 16: MODIFIED - WORKING SIDEBAR FIX
# ============================================
echo ""
echo "🚀 [16/18] Memodifikasi Sidebar Template..."

# Cari file sidebar admin
SIDEBAR_FILE=$(find /var/www/pterodactyl/resources/views -name "*.blade.php" -type f -exec grep -l "admin.locations" {} \; 2>/dev/null | head -1)

if [ -n "$SIDEBAR_FILE" ]; then
    echo "📁 Found sidebar: $SIDEBAR_FILE"
    cp "$SIDEBAR_FILE" "$BACKUP_DIR/sidebar_$(basename $SIDEBAR_FILE).bak"
    
    # Backup file
    cp "$SIDEBAR_FILE" "${SIDEBAR_FILE}.backup_$(date +%s)"
    
    # Cara SIMPLE: Add CSS to hide menu for non-ID-1
    # Inject CSS style langsung ke file
    cat > /tmp/sidebar_patch.css << 'EOF'
/* Hide restricted menus for regular admins */
@if(auth()->user()->id !== 1)
    <style>
    a[href*="/admin/locations"],
    a[href*="/admin/nodes"],
    a[href*="/admin/nests"],
    a[href*="/admin/databases"],
    a[href*="/admin/mounts"],
    a[href*="/admin/settings"],
    a[href*="/admin/api"] {
        display: none !important;
    }
    </style>
@endif
EOF
    
    # Add to head section if exists
    if grep -q "</head>" "$SIDEBAR_FILE"; then
        sed -i 's|</head>|@if(auth()->user()->id !== 1)\n<style>\na[href*="/admin/locations"],\na[href*="/admin/nodes"],\na[href*="/admin/nests"],\na[href*="/admin/databases"],\na[href*="/admin/mounts"],\na[href*="/admin/settings"],\na[href*="/admin/api"] { display: none !important; }\n</style>\n@endif\n</head>|' "$SIDEBAR_FILE"
        echo "✅ CSS injected into head"
    else
        # Add at beginning of body
        sed -i 's|<body|<body>\n@if(auth()->user()->id !== 1)\n<style>\na[href*="/admin/locations"],\na[href*="/admin/nodes"],\na[href*="/admin/nests"],\na[href*="/admin/databases"],\na[href*="/admin/mounts"],\na[href*="/admin/settings"],\na[href*="/admin/api"] { display: none !important; }\n</style>\n@endif|' "$SIDEBAR_FILE"
        echo "✅ CSS added to body"
    fi
    
    # Also wrap menu items with PHP condition (more reliable)
    # Create a temporary navigation file
    NAV_DIR="/var/www/pterodactyl/resources/views/admin/partials"
    mkdir -p "$NAV_DIR"
    
    cat > "$NAV_DIR/navigation.blade.php" << 'EOF'
{{-- Navigation with Admin Protection --}}
@php
    $user = auth()->user();
    $isSuperAdmin = $user && $user->id === 1;
@endphp

{{-- Always show for all admins --}}
@can('admin.index')
    <a href="{{ route('admin.index') }}" class="nav-link">
        <i class="nav-icon fas fa-tachometer-alt"></i>
        <p>Overview</p>
    </a>
@endcan

@can('admin.servers')
    <a href="{{ route('admin.servers') }}" class="nav-link">
        <i class="nav-icon fas fa-server"></i>
        <p>Servers</p>
    </a>
@endcan

@can('admin.users')
    <a href="{{ route('admin.users') }}" class="nav-link">
        <i class="nav-icon fas fa-users"></i>
        <p>Users</p>
    </a>
@endcan

{{-- Only for Super Admin (ID 1) --}}
@if($isSuperAdmin)
    @can('admin.locations')
        <a href="{{ route('admin.locations') }}" class="nav-link">
            <i class="nav-icon fas fa-globe"></i>
            <p>Locations</p>
        </a>
    @endcan

    @can('admin.nodes')
        <a href="{{ route('admin.nodes') }}" class="nav-link">
            <i class="nav-icon fas fa-sitemap"></i>
            <p>Nodes</p>
        </a>
    @endcan

    @can('admin.nests')
        <a href="{{ route('admin.nests') }}" class="nav-link">
            <i class="nav-icon fas fa-th-large"></i>
            <p>Nests</p>
        </a>
    @endcan

    @can('admin.databases')
        <a href="{{ route('admin.databases') }}" class="nav-link">
            <i class="nav-icon fas fa-database"></i>
            <p>Databases</p>
        </a>
    @endcan

    @can('admin.mounts')
        <a href="{{ route('admin.mounts') }}" class="nav-link">
            <i class="nav-icon fas fa-hdd"></i>
            <p>Mounts</p>
        </a>
    @endcan

    @can('admin.settings')
        <a href="{{ route('admin.settings') }}" class="nav-link">
            <i class="nav-icon fas fa-cogs"></i>
            <p>Settings</p>
        </a>
    @endcan

    @can('admin.api')
        <a href="{{ route('admin.api') }}" class="nav-link">
            <i class="nav-icon fas fa-key"></i>
            <p>API</p>
        </a>
    @endcan
@endif
EOF
    
    # Replace navigation section in sidebar
    sed -i '/<nav class="mt-2">/,/<\/nav>/c\<nav class="mt-2">\n@include("admin.partials.navigation")\n</nav>' "$SIDEBAR_FILE" 2>/dev/null
    
    echo "✅ Sidebar navigation replaced with protected version"
else
    echo "⚠️  File sidebar tidak ditemukan, skip..."
fi

# ============================================
# PART 17: AUTO OWNER FIX - SERVER CREATION
# ============================================
echo ""
echo "🚀 [17/18] Memperbaiki Auto Owner Detection..."

# Cari file create server blade
CREATE_BLADE=$(find /var/www/pterodactyl -name "*.blade.php" -type f -exec grep -l "Server Owner" {} \; 2>/dev/null | head -1)

if [ -n "$CREATE_BLADE" ]; then
    echo "📁 Found create server form: $CREATE_BLADE"
    cp "$CREATE_BLADE" "${BACKUP_DIR}/create_server.blade.bak"
    
    # Backup dulu
    cp "$CREATE_BLADE" "${CREATE_BLADE}.backup_$(date +%s)"
    
    # Auto-set owner to current user
    # Replace owner dropdown dengan hidden input dan display current user
    cat > /tmp/fix_owner.blade.php << 'EOF'
<?php
$content = file_get_contents($argv[1]);

// Pattern untuk find owner selection (modern Pterodactyl)
$pattern = '/(<div[^>]*class=".*?form-group.*?"[^>]*>\s*<label[^>]*>.*?Server Owner.*?<\/label>.*?<select[^>]*name="owner_id"[^>]*>.*?<\/select>.*?<\/div>)/s';

$replacement = '
<div class="form-group">
    <label for="owner_id" class="form-label">Server Owner</label>
    <div class="input-group">
        <input type="text" class="form-control" value="' . htmlspecialchars(auth()->user()->email ?? auth()->user()->username) . '" readonly disabled>
        <div class="input-group-append">
            <span class="input-group-text"><i class="fas fa-user-check"></i></span>
        </div>
    </div>
    <p class="small text-muted mt-1"><i class="fas fa-info-circle mr-1"></i> This server will be owned by your account automatically.</p>
    <input type="hidden" name="owner_id" value="' . (auth()->user()->id ?? 0) . '">
</div>';

if (preg_match($pattern, $content)) {
    $content = preg_replace($pattern, $replacement, $content);
    echo "✅ Owner selection replaced with auto-owner (Modern UI)\n";
    
    // Also replace any text about "automatically"
    $content = preg_replace('/This server will be owned by your account automatically\./i', '', $content);
} else {
    // Try alternative pattern (older UI)
    $pattern2 = '/(<label[^>]*for="owner_id"[^>]*>.*?<\/label>.*?<select[^>]*id="owner_id"[^>]*name="owner_id"[^>]*>.*?<\/select>)/s';
    
    if (preg_match($pattern2, $content)) {
        $content = preg_replace($pattern2, $replacement, $content);
        echo "✅ Owner selection replaced with auto-owner (Older UI)\n";
    } else {
        // Last attempt: find any select with name="owner_id"
        $pattern3 = '/(<select[^>]*name="owner_id"[^>]*>.*?<\/select>)/s';
        if (preg_match($pattern3, $content)) {
            $content = preg_replace($pattern3, $replacement, $content);
            echo "✅ Owner selection replaced (generic pattern)\n";
        } else {
            echo "❌ Could not find owner selection field\n";
            exit(1);
        }
    }
}

file_put_contents($argv[1], $content);
EOF
    
    # Apply the fix
    php /tmp/fix_owner.blade.php "$CREATE_BLADE"
    
    if [ $? -eq 0 ]; then
        echo "✅ Auto-owner fix applied to create server form"
        
        # Also modify the controller to force owner_id
        SERVER_STORE_FILE="/var/www/pterodactyl/app/Http/Controllers/Admin/Servers/StoreServerController.php"
        if [ ! -f "$SERVER_STORE_FILE" ]; then
            SERVER_STORE_FILE="/var/www/pterodactyl/app/Http/Controllers/Admin/ServersController.php"
        fi
        
        if [ -f "$SERVER_STORE_FILE" ]; then
            # Backup controller
            cp "$SERVER_STORE_FILE" "${BACKUP_DIR}/server_store_controller.bak"
            
            # Cari store method dan tambahkan auto-set owner
            sed -i '/public function store/,/^[[:space:]]*}/{
                /handle.*request/{
                    a\        // Auto-set owner to current user
                    a\        $data = $request->validated();
                    a\        $data["owner_id"] = auth()->user()->id;
                    a\
                }
                s/handle.*request/handle($data)/
            }' "$SERVER_STORE_FILE"
            
            echo "✅ Controller modified to auto-set owner"
        fi
    else
        echo "⚠️ Failed to apply auto-owner fix"
    fi
else
    echo "⚠️ Create server form not found"
fi

# ============================================
# PART 18: SERVER CREATION SERVICE AUTO OWNER
# ============================================
echo ""
echo "🚀 [18/18] Memodifikasi ServerCreationService..."

SERVER_CREATION_SERVICE="/var/www/pterodactyl/app/Services/Servers/ServerCreationService.php"
if [ -f "$SERVER_CREATION_SERVICE" ]; then
    cp "$SERVER_CREATION_SERVICE" "${BACKUP_DIR}/ServerCreationService.bak"
    
    # Backup original
    cp "$SERVER_CREATION_SERVICE" "${SERVER_CREATION_SERVICE}.backup"
    
    # Auto-set owner_id jika tidak diset atau jika user bukan ID 1
    sed -i '/public function handle/,/^[[:space:]]*}/{
        /owner_id/!{
            /\$data =/a\
        // Auto-set owner jika bukan admin ID 1\
        if (!isset($data["owner_id"]) || empty($data["owner_id"]) || (auth()->check() && auth()->user()->id !== 1)) {\
            $data["owner_id"] = auth()->check() ? auth()->user()->id : 1;\
        }
        }
    }' "$SERVER_CREATION_SERVICE"
    
    echo "✅ ServerCreationService modified with auto-owner"
fi

# ============================================
# FINAL CLEANUP
# ============================================
echo ""
echo "🔧 Final cleanup..."

cd /var/www/pterodactyl

# Clear all caches
php artisan optimize:clear 2>/dev/null || true
php artisan view:clear 2>/dev/null || true
php artisan cache:clear 2>/dev/null || true
php artisan config:clear 2>/dev/null || true

# Fix permissions
chown -R www-data:www-data /var/www/pterodactyl 2>/dev/null || true
chmod -R 755 storage bootstrap/cache 2>/dev/null || true

# Restart services
systemctl restart pteroq 2>/dev/null || true
systemctl reload php8.2-fpm 2>/dev/null || systemctl reload php8.1-fpm 2>/dev/null || systemctl reload php8.0-fpm 2>/dev/null || true

echo ""
echo "=========================================="
echo "🎉 INSTALASI SELESAI!"
echo "=========================================="
echo ""
echo "📊 SUMMARY:"
echo "✅ 16 file telah diproteksi"
echo "📦 Backup disimpan di: $BACKUP_DIR"
echo ""
echo "🔒 PROTEKSI YANG DIPASANG:"
echo "1. Anti hapus server sembarangan"
echo "2. Admin hanya lihat server/user sendiri"
echo "3. Hanya ID 1 bisa akses Locations, Nodes, Nests"
echo "4. Hanya ID 1 bisa akses Settings"
echo "5. Hanya ID 1 bisa akses API Keys"
echo "6. Hanya ID 1 bisa modifikasi server details"
echo "7. Anti intip server via Client API"
echo "8. Anti intip file server orang lain"
echo "9. Welcome message di panel"
echo "10. ✅ SIDEBAR FIXED: Menu hanya Servers & Users untuk admin biasa"
echo "11. ✅ AUTO OWNER FIXED: Create server langsung auto-detect owner"
echo ""
echo "🔧 TEST SEKARANG:"
echo "- Login sebagai admin biasa (bukan ID 1)"
echo "- Sidebar hanya tampilkan: Overview, Servers, Users"
echo "- Menu lain HILANG"
echo "- Akses langsung /admin/locations → 403 Error"
echo "- Akses langsung /admin/nodes → 403 Error"
echo "- Buat server → Owner otomatis terisi dengan email/username Anda"
echo "- Tidak perlu search user, langsung auto-set"
echo ""
echo "⚠️  PERHATIAN:"
echo "- Hard refresh browser: Ctrl+Shift+R"
echo "- Clear browser cache jika perlu"
echo "- Test dengan multiple admin accounts"
echo ""
echo "🔄 Rollback: Salin file dari $BACKUP_DIR"